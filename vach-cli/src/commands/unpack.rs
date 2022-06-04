use std::fs::{self, File};
use std::str::FromStr;
use std::io::{Read, Seek};
use std::path::PathBuf;
use std::time::Instant;

use vach::prelude::{ArchiveConfig, Archive, InternalError};
use vach::rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use vach::crypto_utils;
use indicatif::{ProgressBar, ProgressStyle};

use super::CommandTrait;
use crate::keys::key_names;

pub const VERSION: &str = "0.1.0";

/// This command extracts an archive into the specified output folder
pub struct Evaluator;

impl CommandTrait for Evaluator {
	fn evaluate(&self, args: &clap::ArgMatches) -> anyhow::Result<()> {
		let input_path = match args.value_of(key_names::INPUT) {
			Some(path) => path,
			None => anyhow::bail!("Please provide an input path using the -i or --input key"),
		};

		let output_path = match args.value_of(key_names::OUTPUT) {
			Some(path) => PathBuf::from_str(path)?,
			None => PathBuf::from_str("")?,
		};

		if output_path.is_file() {
			anyhow::bail!("Please provide a directory|folder path as the value of -o | --output")
		};

		let magic: [u8; vach::MAGIC_LENGTH] = match args.value_of(key_names::MAGIC) {
			Some(magic) => magic.as_bytes().try_into()?,
			None => *vach::DEFAULT_MAGIC,
		};

		// Attempting to extract a public key from a -p or -k input
		let public_key = match args.value_of(key_names::KEYPAIR) {
			Some(path) => {
				let file = match File::open(path) {
					Ok(it) => it,
					Err(err) => anyhow::bail!("IOError: {} @ {}", err, path),
				};

				Some(crypto_utils::read_keypair(file)?.public)
			},
			None => match args.value_of(key_names::PUBLIC_KEY) {
				Some(path) => {
					let file = File::open(path)?;
					Some(crypto_utils::read_public_key(file)?)
				},
				None => None,
			},
		};

		// Whether to truncate the original archive after extraction
		let truncate = args.is_present(key_names::TRUNCATE);

		let input_file = match File::open(input_path) {
			Ok(it) => it,
			Err(err) => anyhow::bail!("IOError: {} @ {}", err, input_path),
		};

		// Generate ArchiveConfig using given magic and public key
		let header_config = ArchiveConfig::new(magic, public_key);

		// Parse then extract archive
		let archive = match Archive::with_config(input_file, &header_config) {
			Ok(archive) => archive,
			Err(err) => match err {
				InternalError::NoKeypairError => anyhow::bail!(
					"Please provide a public key or a keypair for use in decryption or signature verification"
				),
				InternalError::MalformedArchiveSource(_) => anyhow::bail!("Unable to validate the archive: {}", err),
				err => anyhow::bail!("Encountered an error: {}", err.to_string()),
			},
		};

		extract_archive(&archive, output_path)?;

		// Delete original archive
		if truncate {
			log::info!("Truncating original archive @ {}", &input_path);
			std::fs::remove_file(input_path)?;
		};

		Ok(())
	}
}

fn extract_archive<T: Read + Seek + Send + Sync>(archive: &Archive<T>, target_folder: PathBuf) -> anyhow::Result<()> {
	// For measuring the time difference
	let time = Instant::now();
	fs::create_dir_all(&target_folder)?;

	let total_size = archive
		.entries()
		.iter()
		.map(|(_, entry)| entry.offset)
		.reduce(|a, b| a + b)
		.unwrap_or(0);

	let pbar = ProgressBar::new(total_size);

	// NOTE: More styling is to come
	pbar.set_style(
		ProgressStyle::default_bar()
			.template(super::PROGRESS_BAR_STYLE)
			.progress_chars("█░-")
			.tick_strings(&[
				"⢀ ", "⡀ ", "⠄ ", "⢂ ", "⡂ ", "⠅ ", "⢃ ", "⡃ ", "⠍ ", "⢋ ", "⡋ ", "⠍⠁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉",
				"⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⢈⠩", "⡀⢙", "⠄⡙", "⢂⠩", "⡂⢘", "⠅⡘", "⢃⠨", "⡃⢐", "⠍⡐", "⢋⠠", "⡋⢀", "⠍⡁",
				"⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⠈⠩", " ⢙", " ⡙", " ⠩", " ⢘", " ⡘", " ⠨",
				" ⢐", " ⡐", " ⠠", " ⢀", " ⡀",
			]),
	);

	// Vector to allow us to window later via .as_slice()
	let entry_vec = archive.entries().iter().map(|a| (a.0, a.1.offset)).collect::<Vec<_>>();

	// ignore the unprofessional match clause
	match entry_vec.as_slice().par_iter().try_for_each(|(id, offset)| {
		// Prevent column from wrapping around
		if let Some((terminal_width, _)) = term_size::dimensions() {
			let mut msg = id.to_string();
			// Make sure progress bar never get's longer than terminal size
			if msg.len() + 140 >= terminal_width {
				msg.truncate(terminal_width - 140);
				msg.push_str("...");
			}

			// Set's the Progress Bar message
			pbar.set_message(msg.to_string());
		};

		// Process filesystem
		let mut save_path = target_folder.clone();
		save_path.push(&id);

		if let Some(parent_dir) = save_path.ancestors().nth(1) {
			fs::create_dir_all(parent_dir)?;
		};

		// Write to file and update process queue
		let mut file = File::create(save_path)?;
		archive.fetch_write(id, &mut file)?;

		// Increment Progress Bar
		pbar.inc(*offset);
		Ok(())
	}) {
		Ok(it) => it,
		Err(err) => return Err(err),
	};

	// Finished extracting
	pbar.finish_and_clear();
	log::info!(
		"Extracted {} files in {}s",
		archive.entries().len(),
		time.elapsed().as_secs_f64()
	);

	Ok(())
}
