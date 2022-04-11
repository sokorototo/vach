use crate::{
	global::{reg_entry::RegistryEntry, flags::Flags},
};

#[cfg(feature = "compression")]
use crate::global::compressor::CompressionAlgorithm;

use std::{io::Read, fmt};

/// Configures how [`Leaf`]s should be compressed.
/// Default is `CompressMode::Never`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "compression")]
#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
pub enum CompressMode {
	/// The data will always be compressed
	Always,
	/// The compressed data is used, only if it is smaller than the original data.
	Detect,
	/// The data is never compressed and is embedded as is.
	Never,
}

#[cfg(feature = "compression")]
impl Default for CompressMode {
	fn default() -> CompressMode {
		CompressMode::Never
	}
}

#[cfg(feature = "multithreaded")]
/// A toggle blanket-trait wrapping around `io::Read` allowing for seamless switching between single or multithreaded execution
pub trait HandleTrait: Read + Send + Sync {}
#[cfg(feature = "multithreaded")]
impl<T: Read + Send + Sync> HandleTrait for T {}

#[cfg(not(feature = "multithreaded"))]
/// A toggle blanket-trait wrapping around `io::Read` allowing for seamless switching between single or multithreaded execution
pub trait HandleTrait: Read {}
#[cfg(not(feature = "multithreaded"))]
impl<T: Read> HandleTrait for T {}

/// A wrapper around an `io::Read` handle.
/// Allows for multiple types of data implementing `io::Read` to be used under one struct.
/// Also used to configure how data will be processed and embedded into an write target.
pub struct Leaf<'a> {
	// The lifetime simply reflects to the [`Builder`]'s lifetime, meaning the handle must live longer than or the same as the Builder
	pub(crate) handle: Box<dyn HandleTrait + 'a>,

	/// The `ID` under which the embedded data will be referenced
	pub id: String,
	/// The version of the content, allowing you to track obsolete data.
	pub content_version: u8,

	/// How a [`Leaf`] should be compressed
	#[cfg(feature = "compression")]
	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	pub compress: CompressMode,
	/// The specific compression algorithm to use

	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	#[cfg(feature = "compression")]
	pub compression_algo: CompressionAlgorithm,

	/// The flags that will go into the archive write target.
	pub flags: Flags,
	/// Use encryption when writing into the target.
	pub encrypt: bool,
	/// Whether to include a signature with this [`Leaf`], defaults to false.
	/// If set to true then a hash generated and validated when loaded.
	/// > *NOTE:* **Turning `sign` on severely hurts the performance of `Archive::fetch(---)`**. This is because signature authentication is an intentionally taxing process, thus preventing brute-forcing of archives.
	pub sign: bool,
}

impl<'a> Leaf<'a> {
	#[inline(always)]
	/// Wrap a [`Leaf`] around the given handle.
	/// Using the `Default` configuration.
	///```
	/// use vach::prelude::Leaf;
	/// use std::io::Cursor;
	///
	/// let leaf = Leaf::from_handle(Cursor::new(vec![]));
	///```
	pub fn from_handle<H: HandleTrait + 'a>(handle: H) -> Leaf<'a> {
		Leaf {
			handle: Box::new(handle),
			..Default::default()
		}
	}

	/// Consume the [Leaf] and return the underlying Boxed handle
	pub fn into_inner(self) -> Box<dyn HandleTrait + 'a> {
		self.handle
	}

	pub(crate) fn to_registry_entry(&self) -> RegistryEntry {
		let mut entry = RegistryEntry::empty();
		entry.content_version = self.content_version;
		entry.flags = self.flags;
		entry
	}

	/// Copy all fields from another [`Leaf`], except for `handle` and `id`
	/// Meant to be used like a setter:
	/// ```rust
	/// use std::io::Cursor;
	/// use vach::prelude::Leaf;
	/// let template = Leaf::default()
	///    .version(12)
	///    .encrypt(false);
	///
	/// let leaf = Leaf::from_handle(Cursor::new(vec![])).template(&template);
	/// assert_eq!(&leaf.content_version, &template.content_version);
	/// assert_eq!(&leaf.encrypt, &template.encrypt);
	/// ```
	pub fn template(self, other: &Leaf<'a>) -> Self {
		Leaf {
			handle: self.handle,
			id: self.id,
			..*other
		}
	}

	// Setters
	/// Setter used to set the [`CompressMode`] of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf, CompressMode};
	///
	/// let leaf = Leaf::default().compress(CompressMode::Always);
	/// ```
	#[cfg(feature = "compression")]
	#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
	pub fn compress(mut self, compress: CompressMode) -> Self {
		self.compress = compress;
		self
	}

	/// Setter used to set the `content_version` of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf};
	///
	/// let leaf = Leaf::default().version(2);
	/// ```
	pub fn version(mut self, content_version: u8) -> Self {
		self.content_version = content_version;
		self
	}

	/// Setter used to set the `id` field of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf};
	///
	/// let leaf = Leaf::default().id("whatzitouya");
	/// ```
	pub fn id(mut self, id: impl ToString) -> Self {
		self.id = id.to_string();
		self
	}

	/// Setter used to set the [`flags`](crate::builder::Flags) field of a [`Leaf`]
	/// ```rust
	/// use vach::prelude::{Leaf, Flags};
	///
	/// let leaf = Leaf::default().flags(Flags::default());
	/// ```
	pub fn flags(mut self, flags: Flags) -> Self {
		self.flags = flags;
		self
	}

	/// Setter for the `encrypt` field
	///```
	/// use vach::prelude::Leaf;
	/// let config = Leaf::default().encrypt(true);
	///```
	pub fn encrypt(mut self, encrypt: bool) -> Self {
		self.encrypt = encrypt;
		self
	}

	/// Setter for the `sign` field
	///```
	/// use vach::prelude::Leaf;
	/// let config = Leaf::default().sign(true);
	///```
	pub fn sign(mut self, sign: bool) -> Self {
		self.sign = sign;
		self
	}

	/// Setter for the `compression_algo` field
	#[cfg(feature = "compression")]
	pub fn compression_algo(mut self, compression_algo: CompressionAlgorithm) -> Self {
		self.compression_algo = compression_algo;
		self
	}
}

impl<'a> Default for Leaf<'a> {
	/// The default leaf holds no bytes at all, this is expected to be used as a stencil|template.
	#[inline(always)]
	fn default() -> Leaf<'a> {
		Leaf {
			id: String::new(),
			handle: Box::<&[u8]>::new(&[]),
			flags: Flags::empty(),
			content_version: 0,
			#[cfg(feature = "compression")]
			compress: CompressMode::Never,
			encrypt: false,
			sign: false,

			#[cfg(feature = "compression")]
			compression_algo: CompressionAlgorithm::LZ4,
		}
	}
}

impl<'a> fmt::Debug for Leaf<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut d = f.debug_struct("Leaf");
		d.field("handle", &"[Box<dyn io::Read>]")
			.field("id", &self.id)
			.field("content_version", &self.content_version)
			.field("flags", &self.flags)
			.field("encrypt", &self.encrypt)
			.field("sign", &self.sign);

		#[cfg(feature = "compression")]
		d.field("compress", &self.compress);

		#[cfg(feature = "compression")]
		d.field("compression_algo", &self.compression_algo);

		d.finish()
	}
}
