use anyhow::{bail, format_err, Error};

/// Parses out a "name" which can be alphanumeric and include dashes.
///
/// Returns `None` if the name part would be empty.
///
/// Returns a tuple with the name and the remainder (not trimmed).
///
/// # Examples
/// ```ignore
/// assert_eq!(match_name("some-name someremainder"), Some(("some-name", " someremainder")));
/// assert_eq!(match_name("some-name@someremainder"), Some(("some-name", "@someremainder")));
/// assert_eq!(match_name(""), None);
/// assert_eq!(match_name(" someremainder"), None);
/// ```
pub fn match_name(line: &str) -> Option<(&str, &str)> {
    let end = line
        .as_bytes()
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || b == b'-'));

    let (name, rest) = match end {
        Some(end) => line.split_at(end),
        None => (line, ""),
    };

    if name.is_empty() {
        None
    } else {
        Some((name, rest))
    }
}

/// Parses up to the next whitespace character or end of the string.
///
/// Returns `None` if the non-whitespace part would be empty.
///
/// Returns a tuple containing the parsed section and the *trimmed* remainder.
pub fn match_non_whitespace(line: &str) -> Option<(&str, &str)> {
    let (text, rest) = line
        .as_bytes()
        .iter()
        .position(|&b| b.is_ascii_whitespace())
        .map(|pos| {
            let (a, b) = line.split_at(pos);
            (a, b.trim_start())
        })
        .unwrap_or((line, ""));
    if text.is_empty() {
        None
    } else {
        Some((text, rest))
    }
}
pub fn parse_bool(value: &str) -> Result<bool, Error> {
    Ok(
        if value == "0"
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("off")
            || value.eq_ignore_ascii_case("no")
        {
            false
        } else if value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("on")
            || value.eq_ignore_ascii_case("yes")
        {
            true
        } else {
            bail!("not a boolean: {value:?}");
        },
    )
}
