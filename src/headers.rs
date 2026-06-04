//! A tiny read-only abstraction over "a bag of HTTP headers".
//!
//! The core needs to *read* header values during verification without binding
//! to any one HTTP library's header type. [`HeaderSource`] is that seam.
//! Lookups MUST be case-insensitive on the header name. Impls are provided for
//! the common owned-pair containers; the `axum` feature adds one for
//! `http::HeaderMap`.

/// Anything the verifier can pull SESAME header values out of.
pub trait HeaderSource {
    /// Return the first value whose name matches `name` case-insensitively.
    fn get(&self, name: &str) -> Option<&str>;
}

impl HeaderSource for [(&str, &str)] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

impl HeaderSource for Vec<(&'static str, String)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl HeaderSource for Vec<(String, String)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}
