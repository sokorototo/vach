mod config;
use super::leaf::{Leaf, CompressMode};
use crate::global::{header::Header, reg_entry::RegistryEntry, types::Flags};
pub use config::BuilderConfig;

use ed25519_dalek::Signer;
use lz4_flex as lz4;
use std::io::{self, BufWriter, Write, Read, Seek, SeekFrom};

/// The archive builder. Provides an interface with which one can configure and build out valid `vach` archives.
pub struct Builder<'a> {
	leafs: Vec<Leaf<'a>>,
}

impl<'a> Default for Builder<'a> {
	#[inline(always)]
	fn default() -> Builder<'a> {
		Builder { leafs: Vec::new() }
	}
}

impl<'a> Builder<'a> {
	/// Instantiates a new `Builder` with an empty processing queue.
	#[inline(always)]
	pub fn new() -> Builder<'a> {
		Builder::default()
	}
	/// Appends a read handle wrapped in a `Leaf` into the processing queue.
	/// The `data` is wrapped in the default `Leaf`.
	/// The second argument is the `ID` with which the embedded data will be tagged
	pub fn add<D: Read + 'a>(&mut self, data: D, id: &str) -> anyhow::Result<()> {
		let leaf = Leaf::from_handle(data).id(id);
		self.add_leaf(leaf);
		Ok(())
	}
	/// Loads all files from a directory and appends them into the processing queue.
	/// A `Leaf` is passed as a template from which the wrapping `Leaf`s shall be based on.
	/// Appended `Leaf`s have an `ID` of: `<directory_name>/<file_name>`. For example: "sounds/footstep.wav", "sample/script.data"
	pub fn add_dir(&mut self, path: &str, template: &Leaf) -> anyhow::Result<()> {
		use std::fs;

		let directory = fs::read_dir(path)?;
		for file in directory {
			let uri = file?.path();

			// BUG: Fix this DUMB DUMB code
			let v = uri
				.iter()
				.map(|u| String::from(u.to_str().unwrap()))
				.collect::<Vec<String>>();

			if !uri.is_dir() {
				// Therefore a file
				let file = fs::File::open(uri)?;
				let leaf = Leaf::from_handle(file)
					.template(template)
					.id(&format!("{}/{}", v[0], v[1]));

				self.leafs.push(leaf);
			}
		}

		Ok(())
	}

	#[inline(always)]
	/// Append a preconstructed `Leaf` into the processing queue.
	pub fn add_leaf(&mut self, leaf: Leaf<'a>) {
		self.leafs.push(leaf);
	}

	/// This iterates over all `Leaf`s in the processing queue, parses them and writes the data out into a `impl Write` target.
	/// Custom *`MAGIC`*, Header flags and a `Keypair` can be presented using the `BuilderConfig` struct.
	/// If a valid `Keypair` is provided, as `Some(keypair)`, then the data will be signed and signatures will be embedded into the archive source.
	pub fn dump<W: Write + Seek>(
		&mut self, mut target: W, config: &BuilderConfig,
	) -> anyhow::Result<usize> {
		// Keep track of how many bytes are written, and where bytes are being written
		let mut size = 0usize;
		let mut reg_offset = 0;
		let mut leaf_offset = Header::BASE_SIZE;

		// Start at the very start of the file
		target.seek(SeekFrom::Start(0))?;

		// Write header in order defined in the spec document
		let mut wtr = BufWriter::new(target);
		wtr.write_all(&config.magic)?;

		// INSERT flags
		let mut temp = config.flags;
		if config.keypair.is_some() {
			temp.force_set(Flags::SIGNED_FLAG, true);
		};
		wtr.write_all(&temp.bits().to_le_bytes())?;

		// Write the version of the Archive Format|Builder|Loader
		wtr.write_all(&crate::VERSION.to_le_bytes())?;
		wtr.write_all(&(self.leafs.len() as u16).to_le_bytes())?;

		// Update how many bytes have been written
		size += Header::BASE_SIZE;
		reg_offset += Header::BASE_SIZE;

		// Calculate the size of the registry
		for leaf in self.leafs.iter() {
			// The size of it's ID, the minimum size of an entry without a signature, and the size of a signature only if a signature is incorporated into the entry
			leaf_offset += leaf.id.len()
				+ RegistryEntry::MIN_SIZE
				+ (if config.keypair.is_some() { crate::SIGNATURE_LENGTH } else { 0 });
		}
		// Start counting the offset of the leafs from the end of the registry

		// Populate the archive glob
		for leaf in self.leafs.iter_mut() {
			let mut entry = leaf.to_registry_entry();
			let mut leaf_bytes = Vec::new();

			// Create and compare compressed leaf data
			match leaf.compress {
				CompressMode::Never => {
					leaf.handle.read_to_end(&mut leaf_bytes)?;
				}
				CompressMode::Always => {
					let mut compressor = lz4::frame::FrameEncoder::new(leaf_bytes);
					io::copy(&mut leaf.handle, &mut compressor)?;
					leaf_bytes = compressor.finish()?;
					entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
				}
				CompressMode::Detect => {
					let mut buffer = Vec::new();
					leaf.handle.read_to_end(&mut buffer)?;

					let mut compressor = lz4::frame::FrameEncoder::new(Vec::new());
					io::copy(&mut buffer.as_slice(), &mut compressor)?;
					let mut compressed_data = compressor.finish()?;

					let ratio = compressed_data.len() as f32 / buffer.len() as f32;
					if ratio < 1f32 {
						entry.flags.force_set(Flags::COMPRESSED_FLAG, true);
						leaf_bytes.append(&mut compressed_data);
					} else {
						buffer.as_slice().read_to_end(&mut leaf_bytes)?;
					};
				}
			}

			let glob_length = leaf_bytes.len();

			// Buffer the contents of the leaf, to be written later
			wtr.seek(SeekFrom::Start(leaf_offset as u64))?;
			wtr.write_all(&leaf_bytes)?;
			size += glob_length;

			entry.location = leaf_offset as u64;
			leaf_offset += glob_length;
			entry.offset = glob_length as u64;

			if let Some(keypair) = &config.keypair {
				// The reason we include the path in the signature is to prevent mangling in the registry,
				// For example, you may mangle the registry, causing this leaf to be addressed by a different reg_entry
				// The path of that reg_entry + The data, when used to validate the signature, will produce an invalid signature. Invalidating the query
				leaf_bytes.extend(leaf.id.as_bytes());
				entry.signature = Some(keypair.sign(&leaf_bytes));
			};

			{
				// Make sure the ID is not too big or else it will break the archive
				if leaf.id.len() >= u16::MAX.into() {
					let mut copy = leaf.id.clone();
					copy.truncate(25);
					anyhow::bail!(format!("The maximum size of any id is: {}. The leaf with ID: {}..., has an ID with length: {}", crate::MAX_ID_LENGTH, copy, leaf.id.len()))
				};

				// Fetch bytes
				let mut entry_bytes = entry.bytes(&(leaf.id.len() as u16));
				entry_bytes.extend(leaf.id.as_bytes());

				// Write to the registry
				wtr.seek(SeekFrom::Start(reg_offset as u64))?;
				wtr.write_all(&entry_bytes)?;

				// Update offsets
				reg_offset += entry_bytes.len();
				size += entry_bytes.len();
			};
		}

		Ok(size)
	}
}
