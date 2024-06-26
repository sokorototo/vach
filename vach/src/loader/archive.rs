use std::{
	collections::HashMap,
	io::{Read, Seek, SeekFrom},
	ops::DerefMut,
	str,
	sync::{Arc, Mutex},
};

use super::resource::Resource;
use crate::global::{
	error::*,
	flags::Flags,
	header::{Header, ArchiveConfig},
	reg_entry::RegistryEntry,
};

#[cfg(feature = "crypto")]
use crate::crypto;

#[cfg(feature = "compression")]
use crate::global::compressor::*;

/// A wrapper for loading data from archive sources.
/// It also provides query functions for fetching [`Resource`]s and [`RegistryEntry`]s.
/// `fetch` and `fetch_mut`, with `fetch` involving a locking operation therefore only requires immutable access.
/// Specify custom `MAGIC` or provide a `PublicKey` for decrypting and authenticating resources using [`ArchiveConfig`].
/// > **A word of advice:**
/// > Do not wrap Archive in a [Mutex] or [RefCell](std::cell::RefCell), use `Archive::fetch`, [`Archive`] employs a [`Mutex`] internally in an optimized manner that reduces time spent locked.
#[derive(Debug)]
pub struct Archive<T> {
	/// Wrapping `handle` in a Mutex means that we only ever lock when reading from the underlying buffer, thus ensuring maximum performance across threads
	/// Since all other work is done per thread
	handle: Mutex<T>,

	// Registry Data
	header: Header,
	entries: HashMap<Arc<str>, RegistryEntry>,

	// Optional parts
	#[cfg(feature = "crypto")]
	decryptor: Option<crypto::Encryptor>,
	#[cfg(feature = "crypto")]
	key: Option<crypto::VerifyingKey>,
}

impl<T> std::fmt::Display for Archive<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let bytes = self
			.entries
			.values()
			.map(|re| re.offset)
			.reduce(|a, b| a + b)
			.unwrap_or(0);

		write!(
			f,
			"[Archive Header] Version: {}, Magic: {:?}, Members: {}, Compressed Size: {bytes}B, Header-Flags: <{:#x} : {:#016b}>",
			self.header.arch_version,
			self.header.magic,
			self.entries.len(),
			self.header.flags.bits,
			self.header.flags.bits,
		)
	}
}

impl<T> Archive<T> {
	/// Consume the [Archive] and return the underlying handle
	/// `None` if underlying
	pub fn into_inner(self) -> Result<T, std::sync::PoisonError<T>> {
		self.handle.into_inner()
	}

	// Decompress and|or decrypt the data
	#[inline(never)]
	fn process(&self, entry: &RegistryEntry, mut raw: Vec<u8>) -> InternalResult<(Vec<u8>, bool)> {
		/* Literally the hottest function in the block (🕶) */

		// buffer_a originally contains the raw data
		let mut decrypted = None;
		let mut is_secure = false;

		// Signature validation
		// Validate signature only if a public key is passed with Some(PUBLIC_KEY)
		#[cfg(feature = "crypto")]
		if let Some(pk) = self.key {
			// If there is an error the data is flagged as invalid
			if let Some(signature) = entry.signature {
				let raw_size = raw.len();

				let entry_bytes = entry.to_bytes(true)?;
				raw.extend_from_slice(&entry_bytes);

				is_secure = pk.verify_strict(&raw, &signature).is_ok();
				raw.truncate(raw_size);
			}
		}

		// Add read layers
		// 1: Decryption layer
		if entry.flags.contains(Flags::ENCRYPTED_FLAG) {
			#[cfg(feature = "crypto")]
			match self.decryptor.as_ref() {
				Some(dc) => {
					decrypted = Some(dc.decrypt(&raw)?);
				},
				None => return Err(InternalError::NoKeypairError),
			}

			#[cfg(not(feature = "crypto"))]
			return Err(InternalError::MissingFeatureError("crypto"));
		}

		// 2: Decompression layer
		if entry.flags.contains(Flags::COMPRESSED_FLAG) {
			#[cfg(feature = "compression")]
			{
				let (source, mut target) = match decrypted {
					// data was decrypted and stored.
					Some(vec) => {
						raw.clear();
						(vec, raw)
					},
					// data was not decrypted nor stored.
					None => {
						let capacity = raw.capacity();
						(raw, Vec::with_capacity(capacity))
					},
				};

				if entry.flags.contains(Flags::LZ4_COMPRESSED) {
					Compressor::new(source.as_slice()).decompress(CompressionAlgorithm::LZ4, &mut target)?
				} else if entry.flags.contains(Flags::BROTLI_COMPRESSED) {
					Compressor::new(source.as_slice()).decompress(CompressionAlgorithm::Brotli(0), &mut target)?
				} else if entry.flags.contains(Flags::SNAPPY_COMPRESSED) {
					Compressor::new(source.as_slice()).decompress(CompressionAlgorithm::Snappy, &mut target)?
				} else {
					return InternalResult::Err(InternalError::OtherError(
						format!(
							"Unable to determine the compression algorithm used for entry: {}",
							entry
						)
						.into(),
					));
				};

				Ok((target, is_secure))
			}

			#[cfg(not(feature = "compression"))]
			Err(InternalError::MissingFeatureError("compression"))
		} else {
			match decrypted {
				Some(decrypted) => Ok((decrypted, is_secure)),
				None => Ok((raw, is_secure)),
			}
		}
	}
}

// INFO: Record Based FileSystem: https://en.wikipedia.org/wiki/Record-oriented_filesystem
impl<T> Archive<T>
where
	T: Seek + Read,
{
	/// Load an [`Archive`] with the default settings from a source.
	/// The same as doing:
	/// ```skip
	/// Archive::with_config(HANDLE, &ArchiveConfig::default())?;
	/// ```
	#[inline(always)]
	pub fn new(handle: T) -> InternalResult<Archive<T>> {
		Archive::with_config(handle, &ArchiveConfig::default())
	}

	/// Given a read handle, this will read and parse the data into an [`Archive`] struct.
	/// Pass a reference to [ArchiveConfig] and it will be used to validate the source and for further configuration.
	pub fn with_config(mut handle: T, config: &ArchiveConfig) -> InternalResult<Archive<T>> {
		// Start reading from the start of the input
		handle.seek(SeekFrom::Start(0))?;

		let header = Header::from_handle(&mut handle)?;
		Header::validate(config, &header)?;

		// Generate and store Registry Entries
		let mut entries = HashMap::new();

		// Construct entries map
		for _ in 0..header.capacity {
			let entry = RegistryEntry::from_handle(&mut handle)?;
			entries.insert(entry.id.clone(), entry);
		}

		let archive = Archive {
			header,
			handle: Mutex::new(handle),
			entries,

			#[cfg(feature = "crypto")]
			key: config.public_key,
			#[cfg(feature = "crypto")]
			decryptor: config
				.public_key
				.as_ref()
				.map(|pk| crypto::Encryptor::new(pk, config.magic)),
		};
		Ok(archive)
	}

	/// Fetch a [`RegistryEntry`] from this [`Archive`].
	/// This can be used for debugging, as the [`RegistryEntry`] holds information on data with the adjacent ID.
	pub fn fetch_entry(&self, id: impl AsRef<str>) -> Option<RegistryEntry> {
		self.entries.get(id.as_ref()).cloned()
	}

	/// Returns an immutable reference to the underlying [`HashMap`]. This hashmap stores [`RegistryEntry`] values and uses `String` keys.
	#[inline(always)]
	pub fn entries(&self) -> &HashMap<Arc<str>, RegistryEntry> {
		&self.entries
	}

	/// Global flags extracted from the `Header` section of the source
	#[inline(always)]
	pub fn flags(&self) -> &Flags {
		&self.header.flags
	}
}

impl<T> Archive<T>
where
	T: Read + Seek,
{
	/// Given a data source and a [`RegistryEntry`], gets the adjacent raw data
	pub(crate) fn read_raw(handle: &mut T, entry: &RegistryEntry) -> InternalResult<Vec<u8>> {
		let mut buffer = Vec::with_capacity(entry.offset as usize + 64);
		handle.seek(SeekFrom::Start(entry.location))?;

		let mut take = handle.take(entry.offset);
		take.read_to_end(&mut buffer)?;

		Ok(buffer)
	}

	/// Cheaper alternative to `fetch` that works best for single threaded applications.
	/// It does not lock the underlying [Mutex], since it requires a mutable reference.
	/// Therefore the borrow checker statically guarantees the operation is safe. Refer to [`Mutex::get_mut`](Mutex).
	pub fn fetch_mut(&mut self, id: impl AsRef<str>) -> InternalResult<Resource> {
		// The reason for this function's unnecessary complexity is it uses the provided functions independently, thus preventing an unnecessary allocation [MAYBE TOO MUCH?]
		if let Some(entry) = self.fetch_entry(&id) {
			let raw = Archive::read_raw(self.handle.get_mut().unwrap(), &entry)?;

			// Prepare contextual variables
			// Decompress and|or decrypt the data
			let (buffer, is_secure) = self.process(&entry, raw)?;

			Ok(Resource {
				content_version: entry.content_version,
				flags: entry.flags,
				data: buffer.into_boxed_slice(),
				authenticated: is_secure,
			})
		} else {
			return Err(InternalError::MissingResourceError(id.as_ref().to_string()));
		}
	}

	/// Fetch a [`Resource`] with the given `ID`.
	/// > Locks the underlying [`Mutex`], for a cheaper non-locking operation refer to `Archive::fetch_mut`
	pub fn fetch(&self, id: impl AsRef<str>) -> InternalResult<Resource> {
		// The reason for this function's unnecessary complexity is it uses the provided functions independently, thus preventing an unnecessary allocation [MAYBE TOO MUCH?]
		if let Some(entry) = self.fetch_entry(&id) {
			let raw = {
				let mut guard = self.handle.lock().unwrap();
				Archive::read_raw(guard.deref_mut(), &entry)?
			};

			// Prepare contextual variables
			// Decompress and|or decrypt the data
			let (buffer, is_secure) = self.process(&entry, raw)?;

			Ok(Resource {
				content_version: entry.content_version,
				flags: entry.flags,
				data: buffer.into_boxed_slice(),
				authenticated: is_secure,
			})
		} else {
			return Err(InternalError::MissingResourceError(id.as_ref().to_string()));
		}
	}
}
