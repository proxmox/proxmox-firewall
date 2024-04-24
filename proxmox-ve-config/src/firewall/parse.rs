use std::fmt;

use anyhow::{bail, format_err, Error};

const NAME_SPECIAL_CHARACTERS: [u8; 2] = [b'-', b'_'];

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
    if !line.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }

    let end = line
        .as_bytes()
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || NAME_SPECIAL_CHARACTERS.contains(&b)));

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

/// parses out all digits and returns the remainder
///
/// returns [`None`] if the digit part would be empty
///
/// Returns a tuple with the digits and the remainder (not trimmed).
pub fn match_digits(line: &str) -> Option<(&str, &str)> {
    let split_position = line.as_bytes().iter().position(|&b| !b.is_ascii_digit());

    let (digits, rest) = match split_position {
        Some(pos) => line.split_at(pos),
        None => (line, ""),
    };

    if !digits.is_empty() {
        return Some((digits, rest));
    }

    None
}

/// Separate a `key: value` line, trimming whitespace.
///
/// Returns `None` if the `key` would be empty.
pub fn split_key_value(line: &str) -> Option<(&str, &str)> {
    line.split_once(':')
        .map(|(key, value)| (key.trim(), value.trim()))
}

/// Parse a boolean.
///
/// values that parse as [`false`]: 0, false, off, no
/// values that parse as [`true`]: 1, true, on, yes
///
/// # Examples
/// ```ignore
/// assert_eq!(parse_bool("false"), Ok(false));
/// assert_eq!(parse_bool("on"), Ok(true));
/// assert!(parse_bool("proxmox").is_err());
/// ```
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

/// Parse the *remainder* of a section line, that is `<whitespace>NAME] #optional comment`.
/// The `kind` parameter is used for error messages and should be the section type.
///
/// Return the name and the optional comment.
pub fn parse_named_section_tail<'a>(
    kind: &'static str,
    line: &'a str,
) -> Result<(&'a str, Option<&'a str>), Error> {
    if line.is_empty() || !line.as_bytes()[0].is_ascii_whitespace() {
        bail!("incomplete {kind} section");
    }

    let line = line.trim_start();
    let (name, line) = match_name(line)
        .ok_or_else(|| format_err!("expected a name for the {kind} at {line:?}"))?;

    let line = line
        .strip_prefix(']')
        .ok_or_else(|| format_err!("expected closing ']' in {kind} section header"))?
        .trim_start();

    Ok(match line.strip_prefix('#') {
        Some(comment) => (name, Some(comment.trim())),
        None if !line.is_empty() => bail!("trailing characters after {kind} section: {line:?}"),
        None => (name, None),
    })
}

// parses a number from a string OR number
pub mod serde_option_number {
    use std::fmt;

    use serde::de::{Deserializer, Error, Visitor};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i64>, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Option<i64>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a numerical value")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom).map(Some)
            }

            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }
        }

        deserializer.deserialize_any(V)
    }
}

// parses a bool from a string OR bool
pub mod serde_option_bool {
    use std::fmt;

    use serde::de::{Deserializer, Error, Visitor};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<bool>, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Option<bool>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a boolean-like value")
            }

            fn visit_bool<E: Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Some(v))
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                super::parse_bool(v).map_err(E::custom).map(Some)
            }

            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }
        }

        deserializer.deserialize_any(V)
    }
}

// parses a comma_separated list of strings
pub mod serde_option_conntrack_helpers {
    use std::fmt;

    use serde::de::{Deserializer, Error, Visitor};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<String>>, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Option<Vec<String>>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("A list of conntrack helpers")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.is_empty() {
                    return Ok(None);
                }

                Ok(Some(v.split(',').map(String::from).collect()))
            }

            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }
        }

        deserializer.deserialize_any(V)
    }
}

// parses a log_ratelimit string: '[enable=]<1|0> [,burst=<integer>] [,rate=<rate>]'
pub mod serde_option_log_ratelimit {
    use std::fmt;

    use serde::de::{Deserializer, Error, Visitor};

    use crate::firewall::types::log::LogRateLimit;

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<LogRateLimit>, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Option<LogRateLimit>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a boolean-like value")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom).map(Some)
            }

            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }
        }

        deserializer.deserialize_any(V)
    }
}

/// `&str` deserializer which also accepts an `Option`.
///
/// Serde's `StringDeserializer` does not.
#[derive(Clone, Copy, Debug)]
pub struct SomeStrDeserializer<'a, E>(serde::de::value::StrDeserializer<'a, E>);

impl<'de, 'a, E> serde::de::Deserializer<'de> for SomeStrDeserializer<'a, E>
where
    E: serde::de::Error,
{
    type Error = E;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.0.deserialize_any(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_some(self.0)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.0.deserialize_str(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.0.deserialize_string(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_enum(self.0)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char
        bytes byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }
}

/// `&str` wrapper which implements `IntoDeserializer` via `SomeStrDeserializer`.
#[derive(Clone, Debug)]
pub struct SomeStr<'a>(pub &'a str);

impl<'a> From<&'a str> for SomeStr<'a> {
    fn from(s: &'a str) -> Self {
        Self(s)
    }
}

impl<'de, 'a, E> serde::de::IntoDeserializer<'de, E> for SomeStr<'a>
where
    E: serde::de::Error,
{
    type Deserializer = SomeStrDeserializer<'a, E>;

    fn into_deserializer(self) -> Self::Deserializer {
        SomeStrDeserializer(self.0.into_deserializer())
    }
}

/// `String` deserializer which also accepts an `Option`.
///
/// Serde's `StringDeserializer` does not.
#[derive(Clone, Debug)]
pub struct SomeStringDeserializer<E>(serde::de::value::StringDeserializer<E>);

impl<'de, E> serde::de::Deserializer<'de> for SomeStringDeserializer<E>
where
    E: serde::de::Error,
{
    type Error = E;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.0.deserialize_any(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_some(self.0)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.0.deserialize_str(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.0.deserialize_string(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_enum(self.0)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char
        bytes byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }
}

/// `&str` wrapper which implements `IntoDeserializer` via `SomeStringDeserializer`.
#[derive(Clone, Debug)]
pub struct SomeString(pub String);

impl From<&str> for SomeString {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

impl From<String> for SomeString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<'de, E> serde::de::IntoDeserializer<'de, E> for SomeString
where
    E: serde::de::Error,
{
    type Deserializer = SomeStringDeserializer<E>;

    fn into_deserializer(self) -> Self::Deserializer {
        SomeStringDeserializer(self.0.into_deserializer())
    }
}

#[derive(Debug)]
pub struct SerdeStringError(String);

impl std::error::Error for SerdeStringError {}

impl fmt::Display for SerdeStringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::de::Error for SerdeStringError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}
