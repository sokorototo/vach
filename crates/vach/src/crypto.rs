#![cfg(feature = "crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
use std::fmt;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::global::error::{InternalError, InternalResult};

/// Encryption - Decryption, A convenient wrapper around [`aes`](aes_gcm) encryption and decryption
pub(crate) struct Encryptor {
	cipher: Aes256Gcm,
}

impl fmt::Debug for Encryptor {
	fn fmt(
		&self,
		f: &mut fmt::Formatter<'_>,
	) -> fmt::Result {
		f.debug_struct("Encryptor").field("cipher", &"<Aes256Gcm>").finish()
	}
}

impl Encryptor {
	pub(crate) fn new(vk: &VerifyingKey) -> Encryptor {
		Encryptor {
			cipher: Aes256Gcm::new_from_slice(vk.as_bytes()).unwrap(),
		}
	}

	pub(crate) fn encrypt(
		&self,
		data: &[u8],
	) -> InternalResult<(Vec<u8>, [u8; crate::NONCE_LENGTH])> {
		let mut nonce = [0u8; crate::NONCE_LENGTH];
		getrandom::fill(&mut nonce).map_err(|_| InternalError::CryptoError(aes_gcm::Error))?;
		let nonce = aes_gcm::Nonce::try_from(nonce.as_slice()).map_err(|_| InternalError::CryptoError(aes_gcm::Error))?;

		let ciphertext = self.cipher.encrypt(&nonce, data)?;
		Ok((ciphertext, *nonce.as_array().unwrap()))
	}

	pub(crate) fn decrypt(
		&self,
		data: &[u8],
		nonce: &[u8; crate::NONCE_LENGTH],
	) -> InternalResult<Vec<u8>> {
		let nonce = aes_gcm::Nonce::try_from(nonce.as_slice()).map_err(|_| InternalError::CryptoError(aes_gcm::Error))?;
		Ok(self.cipher.decrypt(&nonce, data)?)
	}
}
