#![cfg(feature = "net")]

use axum::Router;
use axum::routing::get;
use porte::http_client::HttpClient;

#[tokio::test]
async fn the_default_client_reads_at_most_one_byte_past_one_mebibyte() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route("/big", get(|| async { vec![b'x'; 3 << 20] }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let response = HttpClient::new().get(&format!("http://{address}/big")).await.unwrap();
    assert_eq!((response.status().as_u16(), response.body().len()), (200, (1 << 20) + 1));
}
