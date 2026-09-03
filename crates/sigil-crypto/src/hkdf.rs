use crate::key::MasterKey;
use sigil_core::SecretBytes;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a stable 32-byte application secret for a specific namespace, subject, and purpose.
///
/// HKDF-SHA256:
/// PRK = MasterKey
/// Info = Namespace \0 Subject \0 Purpose
pub fn derive_app_secret(
    master_key: &MasterKey,
    namespace: &str,
    subject: &str,
    purpose: &str,
) -> SecretBytes {
    let mut info = Vec::with_capacity(namespace.len() + subject.len() + purpose.len() + 2);
    info.extend_from_slice(namespace.as_bytes());
    info.push(0);
    info.extend_from_slice(subject.as_bytes());
    info.push(0);
    info.extend_from_slice(purpose.as_bytes());

    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("MasterKey length is 32 bytes, which is valid for HKDF-SHA256 PRK");

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is well within 255 * 32 bytes expansion limit");

    SecretBytes::new(okm.to_vec())
}

/// Compatibility derivation for XDG Desktop Portal Secret v1:
/// PRK = MasterKey
/// Info = "aegis.portal.Secret/v1\0" || app_id
pub fn derive_portal_secret(master_key: &MasterKey, app_id: &str) -> SecretBytes {
    let mut info = b"aegis.portal.Secret/v1\0".to_vec();
    info.extend_from_slice(app_id.as_bytes());

    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("MasterKey length is 32 bytes");

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes output");

    SecretBytes::new(okm.to_vec())
}
