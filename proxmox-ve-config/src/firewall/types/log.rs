use std::fmt;
use std::str::FromStr;

use crate::firewall::parse::parse_bool;
use anyhow::{bail, Error};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Deserialize, Serialize, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "lowercase")]
pub enum LogRateLimitTimescale {
    #[default]
    Second,
    Minute,
    Hour,
    Day,
}

impl FromStr for LogRateLimitTimescale {
    type Err = Error;

    fn from_str(str: &str) -> Result<Self, Error> {
        match str {
            "second" => Ok(LogRateLimitTimescale::Second),
            "minute" => Ok(LogRateLimitTimescale::Minute),
            "hour" => Ok(LogRateLimitTimescale::Hour),
            "day" => Ok(LogRateLimitTimescale::Day),
            _ => bail!("Invalid time scale provided"),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct LogRateLimit {
    enabled: bool,
    rate: i64, // in packets
    per: LogRateLimitTimescale,
    burst: i64, // in packets
}

impl LogRateLimit {
    pub fn new(enabled: bool, rate: i64, per: LogRateLimitTimescale, burst: i64) -> Self {
        Self {
            enabled,
            rate,
            per,
            burst,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn rate(&self) -> i64 {
        self.rate
    }

    pub fn burst(&self) -> i64 {
        self.burst
    }

    pub fn per(&self) -> LogRateLimitTimescale {
        self.per
    }
}

impl Default for LogRateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            rate: 1,
            burst: 5,
            per: LogRateLimitTimescale::Second,
        }
    }
}

impl FromStr for LogRateLimit {
    type Err = Error;

    fn from_str(str: &str) -> Result<Self, Error> {
        let mut limit = Self::default();

        for element in str.split(',') {
            match element.split_once('=') {
                None => {
                    limit.enabled = parse_bool(element)?;
                }
                Some((key, value)) if !key.is_empty() && !value.is_empty() => match key {
                    "enable" => limit.enabled = parse_bool(value)?,
                    "burst" => limit.burst = i64::from_str(value)?,
                    "rate" => match value.split_once('/') {
                        None => {
                            limit.rate = i64::from_str(value)?;
                        }
                        Some((rate, unit)) => {
                            if unit.is_empty() {
                                bail!("empty unit specification")
                            }

                            limit.rate = i64::from_str(rate)?;
                            limit.per = LogRateLimitTimescale::from_str(unit)?;
                        }
                    },
                    _ => bail!("Invalid value for Key found in log_ratelimit!"),
                },
                _ => bail!("invalid value in log_ratelimit"),
            }
        }

        Ok(limit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum LogLevel {
    #[default]
    Nolog,
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl std::str::FromStr for LogLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "nolog" => LogLevel::Nolog,
            "emerg" => LogLevel::Emergency,
            "alert" => LogLevel::Alert,
            "crit" => LogLevel::Critical,
            "err" => LogLevel::Error,
            "warn" => LogLevel::Warning,
            "warning" => LogLevel::Warning,
            "notice" => LogLevel::Notice,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            _ => bail!("invalid log level {s:?}"),
        })
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            LogLevel::Nolog => "nolog",
            LogLevel::Emergency => "emerg",
            LogLevel::Alert => "alert",
            LogLevel::Critical => "crit",
            LogLevel::Error => "err",
            LogLevel::Warning => "warn",
            LogLevel::Notice => "notice",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        })
    }
}

serde_plain::derive_deserialize_from_fromstr!(LogLevel, "valid log level");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_limit() {
        let mut parsed_rate_limit = "1,burst=123,rate=44"
            .parse::<LogRateLimit>()
            .expect("valid rate limit");

        assert_eq!(
            parsed_rate_limit,
            LogRateLimit {
                enabled: true,
                burst: 123,
                rate: 44,
                per: LogRateLimitTimescale::Second,
            }
        );

        parsed_rate_limit = "1".parse::<LogRateLimit>().expect("valid rate limit");

        assert_eq!(parsed_rate_limit, LogRateLimit::default());

        parsed_rate_limit = "enable=0,rate=123/hour"
            .parse::<LogRateLimit>()
            .expect("valid rate limit");

        assert_eq!(
            parsed_rate_limit,
            LogRateLimit {
                enabled: false,
                burst: 5,
                rate: 123,
                per: LogRateLimitTimescale::Hour,
            }
        );

        "2".parse::<LogRateLimit>()
            .expect_err("invalid value for enable");

        "enabled=0,rate=123"
            .parse::<LogRateLimit>()
            .expect_err("invalid key in log ratelimit");

        "enable=0,rate=123,"
            .parse::<LogRateLimit>()
            .expect_err("trailing comma in log rate limit specification");

        "enable=0,rate=123/proxmox,"
            .parse::<LogRateLimit>()
            .expect_err("invalid unit for rate");
    }
}
