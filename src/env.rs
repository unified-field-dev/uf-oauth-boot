//! Process-env helpers for OAuth client ids / flags (no secret logging).

pub fn nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn truthy(key: &str) -> bool {
    std::env::var(key).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}
