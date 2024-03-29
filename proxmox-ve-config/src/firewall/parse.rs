use anyhow::{bail, format_err, Error};

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
