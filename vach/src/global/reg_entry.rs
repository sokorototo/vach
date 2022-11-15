use std::{io::Read, fmt};
use super::{result::InternalResult, flags::Flags};

#[cfg(feature = "crypto")]
use crate::crypto;

/// Stand-alone meta-data for an archive entry(Leaf). This can be fetched without reading from the archive.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
	/// The flags extracted from the archive entry and parsed into a accessible struct
	pub flags: Flags,
	/// The content version of the extracted archive entry
	pub content_version: u8,
	/// The signature of the data in the archive, used when verifying data authenticity
	#[cfg(feature = "crypto")]
	#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
	pub signature: Option<crypto::Signature>,
	/// The location of the file in the archive, as an offset of bytes from the beginning of the file
	pub location: u64,
	/// The offset|size of the [`Leaf`](crate::builder::Leaf), in bytes. This is the actual number of bytes in the leaf endpoint. But the size of the data may vary once processed, ie when decompressed
	pub offset: u64,
}

impl RegistryEntry {
	// (flags) + 1(content version) + 8(location) + 8(offset) + 2(path length) + ..Dynamic
	pub(crate) const MIN_SIZE: usize = Flags::SIZE + 19;

	#[inline(always)]
	pub(crate) fn empty() -> RegistryEntry {
		RegistryEntry {
			flags: Flags::empty(),
			content_version: 0,
			location: 0,
			offset: 0,

			#[cfg(feature = "crypto")]
			signature: None,
		}
	}

	/// Given a read handle, will proceed to read and parse bytes into a [`RegistryEntry`] struct. (de-serialization)
	/// ### Errors
	/// Produces `io` errors and if the bytes in the id section is not valid UTF-8
	pub(crate) fn from_handle<T: Read>(mut handle: T) -> InternalResult<(RegistryEntry, String)> {
		let mut buffer: [u8; RegistryEntry::MIN_SIZE] = [0u8; RegistryEntry::MIN_SIZE];
		handle.read_exact(&mut buffer)?;

		// Construct entry
		let flags = Flags::from_bits(u32::from_le_bytes(buffer[0..4].try_into().unwrap()));
		let content_version = buffer[4];

		let location = u64::from_le_bytes(buffer[5..13].try_into().unwrap());
		let offset = u64::from_le_bytes(buffer[13..21].try_into().unwrap());

		let id_length = u16::from_le_bytes([buffer[21], buffer[22]]);

		#[cfg(feature = "crypto")]
		let mut signature = None;

		/* The data after this is dynamically sized, therefore *MUST* be read conditionally */
		// Only produce a flag from data that is signed
		if flags.contains(Flags::SIGNED_FLAG) {
			let mut sig_bytes: [u8; crate::SIGNATURE_LENGTH] = [0u8; crate::SIGNATURE_LENGTH];
			handle.read_exact(&mut sig_bytes)?;

			// If the `crypto` feature is turned off then the bytes are just read then discarded
			#[cfg(feature = "crypto")]
			{
				use super::error::InternalError;

				let sig = match crypto::Signature::try_from(sig_bytes) {
					Ok(sig) => sig,
					Err(err) => return Err(InternalError::ParseError(err.to_string())),
				};

				signature = Some(sig);
			}
		};

		// Construct ID
		let mut id = String::with_capacity(id_length as usize);
		handle.take(id_length as u64).read_to_string(&mut id)?;

		// Build entry step manually, to prevent unnecessary `Default::default()` call, then changing fields individually
		let entry = RegistryEntry {
			flags,
			content_version,
			location,
			offset,

			#[cfg(feature = "crypto")]
			signature,
		};

		Ok((entry, id))
	}

	/// Serializes a [`RegistryEntry`] struct into an array of bytes
	pub(crate) fn bytes(&self, id_length: &u16) -> Vec<u8> {
		let mut buffer = Vec::with_capacity(RegistryEntry::MIN_SIZE + 64);

		buffer.extend_from_slice(&self.flags.bits().to_le_bytes());
		buffer.extend_from_slice(&self.content_version.to_le_bytes());
		buffer.extend_from_slice(&self.location.to_le_bytes());
		buffer.extend_from_slice(&self.offset.to_le_bytes());
		buffer.extend_from_slice(&id_length.to_le_bytes());

		// Only write signature if one exists
		#[cfg(feature = "crypto")]
		if let Some(signature) = self.signature {
			buffer.extend_from_slice(&signature.to_bytes())
		};

		buffer
	}
}

impl Default for RegistryEntry {
	#[inline(always)]
	fn default() -> RegistryEntry {
		RegistryEntry::empty()
	}
}

impl fmt::Display for RegistryEntry {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"[RegistryEntry] location: {}, length: {}, content_version: {}, flags: {}",
			self.location,
			self.offset,
			self.content_version,
			self.flags.bits()
		)
	}
}
