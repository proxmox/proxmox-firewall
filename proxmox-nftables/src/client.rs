use std::io::prelude::*;
use std::process::{Command, Stdio};

use thiserror::Error;

use crate::command::{CommandOutput, Commands};

#[derive(Error, Debug)]
pub enum NftError {
    #[error("cannot communicate with child process")]
    Io(#[from] std::io::Error),
    #[error("cannot execute nftables commands")]
    Command(String),
}

pub struct NftClient;

impl NftClient {
    fn execute_nft_commands(json: bool, input: &[u8]) -> Result<String, NftError> {
        let mut command = Command::new("nft");

        if json {
            command.arg("-j");
        }

        let mut child = command
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(NftError::from)?;

        if let Err(error) = child.stdin.take().expect("can get stdin").write_all(input) {
            return Err(NftError::from(error));
        };

        let mut error_output = String::new();

        match child
            .stderr
            .take()
            .expect("can get stderr")
            .read_to_string(&mut error_output)
        {
            Ok(_) if !error_output.is_empty() => {
                return Err(NftError::Command(error_output));
            }
            Err(error) => {
                return Err(NftError::from(error));
            }
            _ => (),
        };

        let mut output = String::new();

        if let Err(error) = child
            .stdout
            .take()
            .expect("can get stdout")
            .read_to_string(&mut output)
        {
            return Err(NftError::from(error));
        };

        Ok(output)
    }

    pub fn run_json_commands(commands: &Commands) -> Result<Option<CommandOutput>, NftError> {
        let json = serde_json::to_vec(commands).expect("can serialize commands struct");
        let output = Self::execute_nft_commands(true, &json)?;

        if !output.is_empty() {
            let parsed_output: Option<CommandOutput> = serde_json::from_str(&output).ok();
            return Ok(parsed_output);
        }

        Ok(None)
    }

    pub fn run_commands(commands: &str) -> Result<String, NftError> {
        Self::execute_nft_commands(false, commands.as_bytes())
    }
}
