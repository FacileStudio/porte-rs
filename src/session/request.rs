use http::{Extensions, HeaderMap, Method};

/// The parts of a request porte reads: headers, method and the `tronc::http::Tls` marker.
/// Implemented for `http::Request<B>` and `http::request::Parts`.
pub trait RequestView {
    /// The headers, the extensions and the method.
    fn view(&self) -> View<'_>;
}

/// What [`RequestView::view`] borrows.
pub struct View<'a> {
    /// The request headers.
    pub headers: &'a HeaderMap,
    /// The request extensions.
    pub extensions: &'a Extensions,
    /// The request method.
    pub method: &'a Method,
}

impl<B> RequestView for http::Request<B> {
    fn view(&self) -> View<'_> {
        View { headers: self.headers(), extensions: self.extensions(), method: self.method() }
    }
}

impl RequestView for http::request::Parts {
    fn view(&self) -> View<'_> {
        View { headers: &self.headers, extensions: &self.extensions, method: &self.method }
    }
}
