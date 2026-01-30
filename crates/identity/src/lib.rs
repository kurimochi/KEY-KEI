use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use keyi_core::Packet;
use sui_crypto::{UserSignatureVerifier, Verifier};
use sui_sdk_types::{SimpleSignature, UserSignature};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid signature format (length/flag/pubkey)")]
    InvalidSignatureFormat,
    #[error("Signature verification failed (possible tampering)")]
    SignatureVerificationFailed,
    #[error("Signer address mismatch (pubkey does not match claimed address)")]
    SignerMismatch,
    #[error("Unsupported signature scheme")]
    UnsupportedScheme,
}

fn compute_sui_address(flag: u8, pk_bytes: &[u8]) -> String {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(&[flag]);
    hasher.update(pk_bytes);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    format!("0x{}", hex::encode(out))
}

pub fn verify_packet_signature(packet: &Packet) -> Result<(), IdentityError> {
    let signature = UserSignature::from_bytes(&packet.signature)
        .map_err(|_| IdentityError::InvalidSignatureFormat)?;
    let (scheme_flag, pk_bytes) = match &signature {
        UserSignature::Simple(simple) => match simple {
            SimpleSignature::Ed25519 { public_key, .. } => {
                Ok((0x00u8, public_key.as_bytes().to_vec()))
            }
            SimpleSignature::Secp256k1 { public_key, .. } => {
                Ok((0x01u8, public_key.as_bytes().to_vec()))
            }
            SimpleSignature::Secp256r1 { public_key, .. } => {
                Ok((0x01u8, public_key.as_bytes().to_vec()))
            }
            _ => Err(IdentityError::UnsupportedScheme),
        },
        _ => Err(IdentityError::UnsupportedScheme),
    }?;
    if compute_sui_address(scheme_flag, &pk_bytes) != packet.content.signer {
        return Err(IdentityError::SignerMismatch);
    }

    UserSignatureVerifier::new()
        .verify(&<[u8; 32]>::from(packet.id), &signature)
        .map_err(|_| IdentityError::SignerMismatch)?;
    Ok(())
}
