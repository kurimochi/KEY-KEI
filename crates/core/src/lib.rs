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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Packet {
    pub id: ContentId,
    pub content: Content,
    pub signature: Vec<u8>,
}

impl Content {
    pub fn compute_id(&self) -> ContentId {
        let mut hasher = Keccak256::new();
        let mut cbor_buff: Vec<u8> = Vec::new();
        ciborium::into_writer(self, &mut cbor_buff).unwrap();
        hasher.update(cbor_buff);
        ContentId(hasher.finalize().into())
    }
}

// New types for BlockId, BlockHeader, and Block

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct BlockId([u8; 32]);

impl From<[u8; 32]> for BlockId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<BlockId> for [u8; 32] {
    fn from(value: BlockId) -> Self {
        value.0
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockHeader {
    /// Previous block's ID
    pub previous_block_id: BlockId,
    /// Merkle root of ContentIds of Packets included in this block
    pub merkle_root: [u8; 32],
    /// Unix timestamp of block generation (seconds)
    pub timestamp: u64,
    /// Nonce found during SPoRA mining
    pub nonce: u64,
    /// Hash of the data chunk accessed during SPoRA
    pub spora_proof: [u8; 32],
    /// Mining difficulty for this block
    pub difficulty: [u8; 32],
    /// Block height (distance from the genesis block)
    pub height: u64,
}

impl BlockHeader {
    pub fn compute_id(&self) -> BlockId {
        let mut hasher = Keccak256::new();
        let mut cbor_buff: Vec<u8> = Vec::new();
        // In real code, error handling should be more robust
        ciborium::into_writer(self, &mut cbor_buff).unwrap();
        hasher.update(cbor_buff);
        BlockId(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Block {
    /// ID of the block itself (hash of the Header)
    pub id: BlockId,
    /// Block header
    pub header: BlockHeader,
    /// List of ContentIds of Packets included in this block
    pub packet_ids: Vec<ContentId>,
}
