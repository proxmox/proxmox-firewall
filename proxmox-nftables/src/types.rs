use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::helper::Null;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept(Null),
    Drop(Null),
    Continue(Null),
    Return(Null),
    Goto { target: String },
    Jump { target: String },
}

impl Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            Verdict::Accept(_) => "ACCEPT",
            Verdict::Drop(_) => "DROP",
            Verdict::Continue(_) => "CONTINUE",
            Verdict::Return(_) => "RETURN",
            Verdict::Jump { .. } => "JUMP",
            Verdict::Goto { .. } => "GOTO",
        };

        f.write_str(output)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ElemConfig {
    timeout: Option<i64>,
    expires: Option<i64>,
    comment: Option<String>,
}

impl ElemConfig {
    pub fn new(
        timeout: impl Into<Option<i64>>,
        expires: impl Into<Option<i64>>,
        comment: impl Into<Option<String>>,
    ) -> Self {
        Self {
            timeout: timeout.into(),
            expires: expires.into(),
            comment: comment.into(),
        }
    }
}

