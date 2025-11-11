//! Storage for cryptographic keys and DID documents
//!
//! This module handles secure file I/O for:
//! - **Private keys**: Stored in JWKS format with restricted permissions (0o600)
//! - **DID documents**: Public key bundles in W3C DID format
//!
//! # Security
//! Private key files are created with Unix permissions 0o600 (owner read/write only)
//! to prevent unauthorized access.
//!
//! # Example
//! ```no_run
//! use syft_crypto_protocol::SyftRecoveryKey;
//! use syft_crypto_protocol::storage::{save_private_keys, load_private_keys};
//! use std::path::Path;
//!
//! let recovery_key = SyftRecoveryKey::generate();
//! let private_keys = recovery_key.derive_keys().unwrap();
//!
//! // Save with secure permissions
//! save_private_keys(&private_keys, Path::new("keys.json")).unwrap();
//!
//! // Load back
//! let loaded_keys = load_private_keys(Path::new("keys.json")).unwrap();
//! ```

use crate::error::KeyError;
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::serialization::{
    deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
    serialize_to_did_document, zeroize_json_value,
};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Save private keys to disk with secure permissions (0o600 on Unix, owner-only ACL on Windows).
///
/// The keys are serialized to JWKS format and written to the specified path.
/// Files are created with restrictive permissions from the very first byte and
/// the write is finalized via an atomic rename.
///
/// # Arguments
/// * `keys` - The private keys to save
/// * `path` - Destination file path
///
/// # Errors
/// * `KeyError::JsonError` if serialization fails
/// * `KeyError::StorageError` if file I/O fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::SyftRecoveryKey;
/// use syft_crypto_protocol::storage::save_private_keys;
/// use std::path::Path;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let keys = recovery_key.derive_keys().unwrap();
/// save_private_keys(&keys, Path::new("my_keys.json")).unwrap();
/// ```
pub fn save_private_keys(keys: &SyftPrivateKeys, path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        unix_platform::save_private_keys(keys, path)
    }
    #[cfg(windows)]
    {
        return windows_platform::save_private_keys(keys, path);
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "secure private key storage is only supported on Unix and Windows",
        )
        .into());
    }
}

/// Load private keys from disk.
///
/// Reads a JWKS file and deserializes the private keys.
///
/// # Arguments
/// * `path` - Path to the JWKS file
///
/// # Returns
/// * `Ok(SyftPrivateKeys)` if successful
/// * `Err(KeyError)` if file reading or deserialization fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::storage::load_private_keys;
/// use std::path::Path;
///
/// let keys = load_private_keys(Path::new("my_keys.json")).unwrap();
/// ```
pub fn load_private_keys(path: &Path) -> Result<SyftPrivateKeys, KeyError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut jwks: serde_json::Value = serde_json::from_reader(reader)?;

    let result = deserialize_private_keys(&jwks).map_err(|e| {
        KeyError::SerializationError(format!("Failed to deserialize private keys: {}", e))
    });

    zeroize_json_value(&mut jwks);
    result
}

/// Save DID document to disk.
///
/// Serializes a public key bundle to W3C DID document format and writes to file.
/// This is public data, so no special permissions are set.
///
/// # Arguments
/// * `bundle` - The public key bundle to save
/// * `did_id` - The DID identifier (e.g., "did:web:syftbox.net:alice%40example.com")
/// * `path` - Destination file path
///
/// # Errors
/// * `KeyError::JsonError` if serialization fails
/// * `KeyError::StorageError` if file I/O fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::SyftRecoveryKey;
/// use syft_crypto_protocol::storage::save_did_document;
/// use std::path::Path;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();
/// save_did_document(&bundle, "did:web:example.com:alice", Path::new("did.json")).unwrap();
/// ```
pub fn save_did_document(
    bundle: &SyftPublicKeyBundle,
    did_id: &str,
    path: &Path,
) -> Result<(), KeyError> {
    // Serialize to DID document format
    let did_doc = serialize_to_did_document(bundle, did_id).map_err(|e| {
        KeyError::SerializationError(format!("Failed to serialize DID document: {}", e))
    })?;

    // Convert to pretty-printed JSON string
    let json_string = serde_json::to_string_pretty(&did_doc)?;

    // Write to file
    let mut file = File::create(path)?;
    file.write_all(json_string.as_bytes())?;

    Ok(())
}

/// Load DID document from disk.
///
/// Reads a W3C DID document file and deserializes the public key bundle.
/// Verifies signatures during deserialization.
///
/// # Arguments
/// * `path` - Path to the DID document file
///
/// # Returns
/// * `Ok(SyftPublicKeyBundle)` if successful and signatures are valid
/// * `Err(KeyError)` if file reading, deserialization, or signature verification fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::storage::load_did_document;
/// use std::path::Path;
///
/// let bundle = load_did_document(Path::new("did.json")).unwrap();
/// ```
pub fn load_did_document(path: &Path) -> Result<SyftPublicKeyBundle, KeyError> {
    // Read file contents
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse JSON
    let did_doc: serde_json::Value = serde_json::from_str(&contents)?;

    // Deserialize and verify signatures
    let bundle = deserialize_from_did_document(&did_doc).map_err(|e| {
        KeyError::SerializationError(format!("Failed to deserialize DID document: {}", e))
    })?;

    Ok(bundle)
}

fn next_temp_suffix() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

struct TempFileGuard {
    path: PathBuf,
    persisted: bool,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            persisted: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&mut self) {
        self.persisted = true;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
mod unix_platform {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    pub(super) fn save_private_keys(keys: &SyftPrivateKeys, path: &Path) -> Result<(), KeyError> {
        let mut jwks = serialize_private_keys(keys).map_err(|e| {
            KeyError::SerializationError(format!("Failed to serialize private keys: {}", e))
        })?;

        let result = (|| {
            let (mut file, mut guard) = create_secure_temp_file(path)?;
            {
                let mut writer = BufWriter::new(&mut file);
                serde_json::to_writer_pretty(&mut writer, &jwks)?;
                writer.flush()?;
            }
            file.sync_all()?;
            drop(file);
            fs::rename(guard.path(), path)?;
            guard.persist();
            Ok(())
        })();

        zeroize_json_value(&mut jwks);
        result
    }

    fn create_secure_temp_file(path: &Path) -> Result<(File, TempFileGuard), KeyError> {
        use std::io::ErrorKind;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "keys".to_string());

        for _ in 0..16 {
            let suffix = next_temp_suffix();
            let candidate = parent.join(format!(
                "{}.{}.{suffix:016x}.tmp",
                file_name,
                std::process::id()
            ));

            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&candidate)
            {
                Ok(file) => return Ok((file, TempFileGuard::new(candidate))),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "Unable to create unique temporary key file",
        )
        .into())
    }
}

#[cfg(windows)]
mod windows_platform {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::ptr;

    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        MOVEFILE_REPLACE_EXISTING, MoveFileExW,
    };

    const SECURE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";

    pub(super) fn save_private_keys(keys: &SyftPrivateKeys, path: &Path) -> Result<(), KeyError> {
        let mut jwks = serialize_private_keys(keys).map_err(|e| {
            KeyError::SerializationError(format!("Failed to serialize private keys: {}", e))
        })?;

        let result = (|| {
            let (mut file, mut guard) = create_secure_temp_file(path)?;
            {
                let mut writer = BufWriter::new(&mut file);
                serde_json::to_writer_pretty(&mut writer, &jwks)?;
                writer.flush()?;
            }
            file.sync_all()?;
            drop(file);
            atomic_rename(guard.path(), path)?;
            guard.persist();
            Ok(())
        })();

        zeroize_json_value(&mut jwks);
        result
    }

    fn create_secure_temp_file(path: &Path) -> Result<(File, TempFileGuard), KeyError> {
        use std::io::ErrorKind;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "keys".to_string());

        for _ in 0..16 {
            let suffix = next_temp_suffix();
            let candidate = parent.join(format!(
                "{}.{}.{suffix:016x}.tmp",
                file_name,
                std::process::id()
            ));

            match create_restrictive_file(&candidate) {
                Ok(file) => return Ok((file, TempFileGuard::new(candidate))),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "Unable to create unique temporary key file",
        )
        .into())
    }

    fn create_restrictive_file(path: &Path) -> io::Result<File> {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let sddl_w = wide_from_str(SECURE_SDDL);
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };

        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor as *mut std::ffi::c_void,
            bInheritHandle: 0,
        };

        let path_w = wide_from_path(path);
        let handle = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
                &mut security_attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };

        let result = if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
        };

        unsafe {
            LocalFree(descriptor as isize);
        }

        result
    }

    fn atomic_rename(src: &Path, dst: &Path) -> io::Result<()> {
        let src_w = wide_from_path(src);
        let dst_w = wide_from_path(dst);

        let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };

        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wide_from_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn wide_from_str(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }
}
