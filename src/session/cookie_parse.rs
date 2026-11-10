use http::HeaderMap;
use http::header::COOKIE;

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .find_map(|(_, raw)| parse_value(raw))
}

fn parse_value(raw: &str) -> Option<String> {
    let unquoted = raw.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(raw);
    let valid = unquoted.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b';' && b != b'\\');
    valid.then(|| unquoted.to_owned())
}
