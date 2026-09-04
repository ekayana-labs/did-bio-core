//! Minimal Unix-timestamp -> XML datetime formatting.
//!
//! Resolution metadata reports `updated` as an XML datetime (spec Section 6.2
//! step 9). This avoids a date time dependency: days from civil algorithm,
//! UTC only, whole seconds.

/// Format a Unix timestamp as an XML datetime, e.g. `2026-07-23T04:10:00Z`.
pub fn xml_datetime(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs = unix_seconds.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::xml_datetime;

    #[test]
    fn known_instants() {
        assert_eq!(xml_datetime(0), "1970-01-01T00:00:00Z");
        assert_eq!(xml_datetime(86_399), "1970-01-01T23:59:59Z");
        // leap day
        assert_eq!(xml_datetime(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(xml_datetime(1_753_228_800), "2025-07-23T00:00:00Z");
        // before the epoch (not produced by the registry, but must not panic)
        assert_eq!(xml_datetime(-1), "1969-12-31T23:59:59Z");
    }
}
