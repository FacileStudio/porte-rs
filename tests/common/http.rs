use axum::body::Body;
use axum::response::Response;
use http::Request;
use http_body_util::BodyExt;
use tower::{Service, ServiceExt};

pub struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: String,
}

impl Answer {
    pub fn set_cookies(&self) -> Option<Vec<String>> {
        let values: Vec<String> =
            self.headers.get_all("set-cookie").iter().map(|value| value.to_str().unwrap().to_owned()).collect();
        (!values.is_empty()).then_some(values)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).map(|value| value.to_str().unwrap().to_owned())
    }
}

pub async fn send<S>(service: S, request: Request<Body>) -> Answer
where
    S: Service<Request<Body>, Response = Response, Error = std::convert::Infallible>,
{
    let response = service.oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Answer { status, headers, body: String::from_utf8(bytes.to_vec()).unwrap() }
}
