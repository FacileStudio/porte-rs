use percent_encoding::percent_decode_str;

/// Parses an `application/x-www-form-urlencoded` body as strictly as Go `url.ParseQuery`: a
/// malformed escape or a `;` in a key is an error.
pub(crate) fn parse_form(body: &str) -> Result<Vec<(String, String)>, ()> {
    let mut pairs = Vec::new();
    for part in body.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        if key.contains(';') {
            return Err(());
        }
        pairs.push((unescape(key)?, unescape(value)?));
    }
    Ok(pairs)
}

fn unescape(raw: &str) -> Result<String, ()> {
    let bytes = raw.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%' && !(bytes.get(index + 1..index + 3).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)))
        {
            return Err(());
        }
    }
    let plus = raw.replace('+', " ");
    Ok(percent_decode_str(&plus).decode_utf8_lossy().into_owned())
}
