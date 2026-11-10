use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

const QUERY: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~').remove(b' ');

/// Escapes a value the way Go `url.QueryEscape` does: unreserved bytes stay, a space becomes
/// `+`, everything else is percent-encoded.
pub(crate) fn query_escape(value: &str) -> String {
    utf8_percent_encode(value, QUERY).to_string().replace(' ', "+")
}

/// Encodes pairs the way Go `url.Values.Encode` does: sorted by key, insertion order kept
/// within a key.
pub(crate) fn encode_sorted(pairs: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .iter()
        .map(|(key, value)| format!("{}={}", query_escape(key), query_escape(value)))
        .collect::<Vec<_>>()
        .join("&")
}
