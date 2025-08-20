use std::borrow::Cow;

use vach::crypto_utils::gen_keypair;
use crate::{utils, cli};

// Default keypair write destination
const DEFAULT_KEYPAIR_FILE_NAME: &str = "keypair.kp";

/// This command is used to generate keypair
pub struct Subcommand;

impl super::CommandTrait for Subcommand {
	fn version() -> &'static str {
		"0.2"
	}

	fn evaluate(&self, args: cli::CommandLine) -> anyhow::Result<()> {
		let cli::Command::GenKeypair { output, split_key } = args.command else {
			anyhow::bail!("Wrong implementation invoked for subcommand")
		};

		let output_path = match &output {
			Some(path) => path.to_string_lossy(),
			None => Cow::Borrowed(DEFAULT_KEYPAIR_FILE_NAME),
		};

		let kp = gen_keypair();
		if split_key {
			let trimmed = output_path.trim_end_matches(".kp");

			let mut sk_path = trimmed.to_string();
			sk_path.push_str(".sk");

			let mut pk_path = trimmed.to_string();
			pk_path.push_str(".pk");

			utils::create_and_write_to_file(&sk_path, &kp.to_bytes())?;
			println!("Secret Key successfully generated and saved in: {}", sk_path);

			utils::create_and_write_to_file(&pk_path, &kp.verifying_key().to_bytes())?;
			println!("Public Key successfully generated and saved in: {}", pk_path);
		} else {
			utils::create_and_write_to_file(&output_path, &kp.to_keypair_bytes())?;
			println!("KeyPair successfully generated and saved in: {}", output_path);
		}

		Ok(())
	}
}
