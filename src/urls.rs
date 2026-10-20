//! URLs in text, as MobSF finds them (`MobSF/utils.py::URL_REGEX`, `shared_func.py::
//! url_n_email_extract`), and the host each names.

use std::sync::LazyLock;

use regex::Regex;

/// MobSF's `URL_REGEX`, case-insensitive with Unicode word characters as in Python.
static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%'{}-]+)"#,
    )
    .expect("MobSF's URL pattern compiles")
});

/// Schemes whose URLs name a network host.
const NETWORK_SCHEMES: [&str; 6] = ["http", "https", "ftp", "ftps", "sftp", "sftps"];

/// Every URL-like string in `text`, as MobSF's `URL_REGEX.findall` returns them.
pub fn urls(text: &str) -> Vec<&str> {
    // Cheap test first: most strings hold no URL. Every match has `://`, `www`, or ends its
    // scheme in `ta:` (data) or `pt:` (javascript).
    let bytes = text.as_bytes();
    let maybe = bytes.windows(3).any(|window| {
        window == b"://"
            || window.eq_ignore_ascii_case(b"www")
            || window.eq_ignore_ascii_case(b"ta:")
            || window.eq_ignore_ascii_case(b"pt:")
    });
    if !maybe {
        return Vec::new();
    }
    URL.find_iter(text).map(|found| found.as_str()).collect()
}

/// The host a URL names, lower-cased: for `http`, `https`, `ftp`, `ftps`, `sftp` and `sftps`
/// URLs and bare `www.` names; `None` for other schemes and for hosts that are not domain names
/// (no dot, characters outside letters, digits, `-` and `.`, no letter in the last label).
pub fn host_of(url: &str) -> Option<String> {
    let lowered = url.to_ascii_lowercase();
    let rest = match lowered.split_once("://") {
        Some((scheme, rest)) if NETWORK_SCHEMES.contains(&scheme) => rest,
        Some(_) => return None,
        None if lowered.starts_with("www") => lowered.as_str(),
        None => return None,
    };
    let authority = rest.split(['/', '?', '#', '\\', '\'', '"']).next()?;
    let host_and_port = authority.rsplit('@').next()?;
    let host = host_and_port.split(':').next()?.trim_end_matches('.');
    let valid = host.contains('.')
        && !host.starts_with(['.', '-'])
        && !host.ends_with('-')
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '.' || character == '-'
        })
        && host.rsplit('.').next().is_some_and(|label| {
            label
                .chars()
                .any(|character| character.is_ascii_alphabetic())
        });
    valid.then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_hosts() {
        assert_eq!(
            urls("see https://api.example.com/v1?x=1 and www.example.org/a"),
            ["https://api.example.com/v1?x=1", "www.example.org/a"]
        );
        assert!(urls("no links here").is_empty());
        assert_eq!(
            host_of("HTTPS://user:pw@Api.Example.com:8443/path").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            host_of("www.example.org/a").as_deref(),
            Some("www.example.org")
        );
        assert_eq!(host_of("https://10.0.0.1/x"), None);
        assert_eq!(host_of("file:///etc/hosts"), None);
        assert_eq!(host_of("https://localhost/x"), None);
        assert_eq!(
            host_of("https://graph.facebook.com'"),
            Some("graph.facebook.com".to_owned())
        );
    }
}
