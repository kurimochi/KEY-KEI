use std::fmt;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct ContentId([u8; 32]);

impl From<[u8; 32]> for ContentId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<ContentId> for [u8; 32] {
    fn from(value: ContentId) -> Self {
        value.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Content {
    pub creation: Vec<u8>,
    pub lac: ciborium::Value,
    pub parents: Vec<ContentId>,
    pub signer: String,
}

pub struct Packet {
    pub id: ContentId,
    pub content: Content,
    pub signature: Vec<u8>,
}

impl Content {
    pub fn compute_id(&self) -> Result<ContentId, Box<dyn std::error::Error>> {
        let mut hasher = Keccak256::new();
        let mut cbor_buff: Vec<u8> = Vec::new();
        ciborium::into_writer(self, &mut cbor_buff)?;
        hasher.update(cbor_buff);
        Ok(ContentId(hasher.finalize().into()))
    }
}
