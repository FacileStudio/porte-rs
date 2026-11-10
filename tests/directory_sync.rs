#![cfg(feature = "directory")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use http::Request;
use porte::directory::{Apply, Client, DirectoryError, SYNC_PATH, Snapshot, Syncer};
use porte::http_client::{HttpClient, HttpRequest, HttpResponse, Transport, TransportError};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

struct Registre {
    version: Mutex<i64>,
    pulls: AtomicUsize,
}

#[async_trait::async_trait]
impl Transport for Registre {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.pulls.fetch_add(1, Ordering::SeqCst);
        let body = format!("{{\"version\":{}}}", self.version.lock().unwrap());
        Ok(http::Response::builder().status(200).body(body.into_bytes()).unwrap())
    }
}

#[derive(Default)]
struct Applied(Mutex<Vec<i64>>);

#[async_trait::async_trait]
impl Apply for Applied {
    async fn apply(&self, snapshot: &Snapshot) -> Result<(), DirectoryError> {
        self.0.lock().unwrap().push(snapshot.version);
        Ok(())
    }
}

fn syncer() -> (Syncer, Arc<Registre>, Arc<Applied>) {
    let registre = Arc::new(Registre { version: Mutex::new(1), pulls: AtomicUsize::new(0) });
    let client = Client {
        issuer: "https://sso.test".into(),
        client_id: "app".into(),
        client_secret: "secret".into(),
        http: HttpClient::from_transport(registre.clone()),
    };
    let applied = Arc::new(Applied::default());
    (Syncer::new(client, applied.clone(), Duration::from_secs(300)), registre, applied)
}

#[tokio::test]
async fn a_version_is_applied_once() {
    let (syncer, registre, applied) = syncer();
    syncer.sync().await.unwrap();
    syncer.sync().await.unwrap();
    *registre.version.lock().unwrap() = 2;
    syncer.sync().await.unwrap();
    assert_eq!(*applied.0.lock().unwrap(), vec![1, 2]);
}

#[tokio::test]
async fn the_nudge_answers_202_to_a_post_only() {
    let (syncer, _, _) = syncer();
    let app: Router = Router::new().route(SYNC_PATH, syncer.nudge_route());
    let post = app.clone().oneshot(Request::post(SYNC_PATH).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(post.status(), 202);
    let get = app.oneshot(Request::get(SYNC_PATH).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(get.status(), 405);
}

#[tokio::test(start_paused = true)]
async fn the_loop_pulls_at_boot_after_a_nudge_and_on_the_tick() {
    let (syncer, registre, applied) = syncer();
    let shutdown = CancellationToken::new();
    let running = tokio::spawn({
        let (syncer, shutdown) = (syncer.clone(), shutdown.clone());
        async move { syncer.run(shutdown).await }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(registre.pulls.load(Ordering::SeqCst), 1, "no pull at boot");
    *registre.version.lock().unwrap() = 2;
    syncer.nudge();
    syncer.nudge();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(registre.pulls.load(Ordering::SeqCst), 1, "the nudge did not wait for its debounce");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(registre.pulls.load(Ordering::SeqCst), 2, "two nudges inside the debounce did not fold into one pull");
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert_eq!(registre.pulls.load(Ordering::SeqCst), 3, "the interval did not pull");
    assert_eq!(*applied.0.lock().unwrap(), vec![1, 2]);
    shutdown.cancel();
    running.await.unwrap();
}
