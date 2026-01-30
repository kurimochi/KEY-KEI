use ciborium::into_writer;
use keyi_core::{Block, BlockHeader, ContentId, Packet};
use keyi_storage::{Storage, StorageError};
use rand::RngCore;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
use rs_merkle::{MerkleTree, algorithms::Keccak256 as MerkleKeccak256};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// Constants
const CHUNK_SIZE: usize = 256 * 1024; // 256 KiB, as per ANS-103
const SUBSPACES_COUNT: u64 = 1000; // Example value for pick_recall_byte, needs to be specified in protocol
const SEARCH_SPACE_PERCENTAGE: f64 = 0.1; // 10% of weave size for pick_recall_byte

#[derive(Debug, Error)]
pub enum MinerError {
    #[error("Cannot mine a block with no packets")]
    NoPackets,
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Failed to build Merkle root, likely due to empty packet list")]
    MerkleRootError,
    #[error("RandomX error: {0}")]
    RandomX(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid hash length")]
    InvalidHashLength,
    #[error("Unknown error")]
    Unknown,
}

pub struct MineBlockOptions<'a> {
    pub previous_block_header: &'a BlockHeader,
    pub packets: &'a [Packet],
    pub storage: &'a mut Storage,
    pub difficulty: [u8; 32],
}

pub struct Miner {
    cache: RandomXCache,
    dataset: RandomXDataset,
    flags: RandomXFlag,
}

impl Miner {
    /// Creates a new Miner, initializing the expensive RandomX Cache and Dataset.
    /// This should be done once per mining process.
    pub fn new(flags: RandomXFlag, key: &[u8]) -> Result<Self, MinerError> {
        eprintln!("DEBUG: Miner::new - Allocating RandomX cache...");
        let cache = RandomXCache::new(flags, key)
            .map_err(|e| MinerError::RandomX(format!("Failed to allocate RandomX cache: {}", e)))?;
        eprintln!("DEBUG: Miner::new - RandomX cache allocated.");

        eprintln!("DEBUG: Miner::new - Allocating RandomX dataset...");
        let dataset = RandomXDataset::new(flags, cache.clone(), 0).map_err(|e| {
            MinerError::RandomX(format!("Failed to allocate RandomX dataset: {}", e))
        })?;
        eprintln!("DEBUG: Miner::new - RandomX dataset allocated.");

        Ok(Self {
            cache,
            dataset,
            flags,
        })
    }

    pub fn mine_block(&self, options: MineBlockOptions) -> Result<Block, MinerError> {
        if options.packets.is_empty() {
            return Err(MinerError::NoPackets);
        }

        // 1. Prepare: Calculate Merkle Root
        let packet_ids: Vec<ContentId> = options.packets.iter().map(|p| p.id).collect();
        let leaves: Vec<[u8; 32]> = packet_ids.iter().map(|id| (*id).into()).collect();
        let merkle_tree = MerkleTree::<MerkleKeccak256>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().ok_or(MinerError::MerkleRootError)?;

        let previous_block_id = options.previous_block_header.compute_id();
        let height = options.previous_block_header.height + 1;

        let mut rng = rand::rng();

        // Create VM using pre-initialized cache and dataset
        eprintln!("DEBUG: Miner::mine_block - Creating RandomX VM...");
        let vm = RandomXVM::new(
            self.flags,
            Some(self.cache.clone()),
            Some(self.dataset.clone()),
        )
        .map_err(|e| MinerError::RandomX(format!("Failed to create RandomX VM: {}", e)))?;
        eprintln!("DEBUG: Miner::mine_block - RandomX VM created.");

        // 2. Mining Loop (SPoRA algorithm)
        let mut loop_count = 0;
        loop {
            loop_count += 1;
            if loop_count % 1000 == 0 {
                eprintln!("DEBUG: Miner::mine_block - Mining loop iteration: {}", loop_count);
            }
            
            let nonce: u64 = rng.next_u64();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Candidate BlockHeader (spora_proof will be filled later if chunk found)
            let mut candidate_header = BlockHeader {
                previous_block_id,
                merkle_root,
                timestamp,
                nonce,
                spora_proof: [0; 32], // Temporary dummy value
                difficulty: options.difficulty,
                height,
            };

            // Calculate H0 (Slow Hash) - using RandomX on serialized candidate_header
            let mut header_cbor_buff: Vec<u8> = Vec::new();
            into_writer(&candidate_header, &mut header_cbor_buff)
                .map_err(|e| MinerError::Serialization(e.to_string()))?;

            let h0_vec = vm
                .calculate_hash(&header_cbor_buff)
                .map_err(|e| MinerError::RandomX(format!("RandomX H0 hash error: {}", e)))?;
            let h0: [u8; 32] = h0_vec
                .try_into()
                .map_err(|_| MinerError::InvalidHashLength)?;

            // Calculate Recall Byte - ANS-103 pick_recall_byte
            let recall_byte = pick_recall_byte(
                &h0,
                &Into::<[u8; 32]>::into(previous_block_id), // PrevH
                options.storage.get_weave_size(),
            )?;

            // Get data chunk from storage
            let chunk = match options.storage.get_chunk(recall_byte, CHUNK_SIZE) {
                Ok(c) => c,
                Err(StorageError::OutOfBounds) => {
                    eprintln!("DEBUG: Miner::mine_block - OutOfBounds for recall_byte: {}. Weave size: {}", recall_byte, options.storage.get_weave_size());
                    continue // Try new nonce if chunk is out of bounds
                },
                Err(e) => return Err(MinerError::Storage(e)),
            };

            // Calculate spora_proof (hash of the chunk)
            let spora_proof = Keccak256::digest(&chunk).into();

            // Update candidate_header with actual spora_proof
            candidate_header.spora_proof = spora_proof;

            // Calculate SolutionHash (Fast Hash) - randomx_hash(concat(H0, PrevH, Timestamp, Chunk))
            let mut solution_input = Vec::new();
            solution_input.extend_from_slice(&h0);
            solution_input.extend_from_slice(&Into::<[u8; 32]>::into(previous_block_id));
            solution_input.extend_from_slice(&timestamp.to_be_bytes());
            solution_input.extend_from_slice(&spora_proof);

            let solution_hash_vec = vm.calculate_hash(&solution_input).map_err(|e| {
                MinerError::RandomX(format!("RandomX SolutionHash hash error: {}", e))
            })?;
            let solution_hash: [u8; 32] = solution_hash_vec
                .try_into()
                .map_err(|_| MinerError::InvalidHashLength)?;

            // Check difficulty
            if solution_hash < options.difficulty {
                // Found a valid block!
                let block_id = candidate_header.compute_id();
                let block = Block {
                    id: block_id,
                    header: candidate_header,
                    packet_ids: packet_ids.clone(),
                };

                return Ok(block);
            }
        }
    }
}

// ANS-103: pick_recall_byte implementation
fn pick_recall_byte(
    h0: &[u8; 32],
    prev_h: &[u8; 32],
    search_space_upper_bound: u64,
) -> Result<u64, MinerError> {
    if search_space_upper_bound == 0 {
        eprintln!("DEBUG: pick_recall_byte - search_space_upper_bound is 0. Returning 0.");
        return Ok(0); // Handle empty weave case
    }

    let h0_num = u64::from_be_bytes(
        h0[0..8]
            .try_into()
            .map_err(|_| MinerError::InvalidHashLength)?,
    );
    let _prev_h_num = u64::from_be_bytes(
        prev_h[0..8]
            .try_into()
            .map_err(|_| MinerError::InvalidHashLength)?,
    );

    let subspace_number = h0_num % SUBSPACES_COUNT;
    let search_space_size = (search_space_upper_bound as f64 * SEARCH_SPACE_PERCENTAGE) as u64;
    let even_subspace_size = search_space_upper_bound / SUBSPACES_COUNT;
    let search_subspace_size = search_space_size / SUBSPACES_COUNT;

    let subspace_start = subspace_number * even_subspace_size;
    let subspace_actual_size = std::cmp::min(
        search_space_upper_bound.saturating_sub(subspace_start),
        even_subspace_size,
    );
    eprintln!("DEBUG: pick_recall_byte - search_space_upper_bound: {}, subspace_number: {}, search_space_size: {}, even_subspace_size: {}, search_subspace_size: {}, subspace_start: {}, subspace_actual_size: {}",
        search_space_upper_bound, subspace_number, search_space_size, even_subspace_size, search_subspace_size, subspace_start, subspace_actual_size);

    // If subspace_actual_size is 0, subsequent modulo operations might cause issues or return 0,
    // leading to infinite OutOfBounds. Return an error or a special value.
    if subspace_actual_size == 0 {
        eprintln!("DEBUG: pick_recall_byte - subspace_actual_size is 0. Returning 0 (will likely cause OutOfBounds).");
        return Ok(0); 
    }

    let encoded_subspace_number_hash_input = {
        let mut v = Vec::new();
        v.extend_from_slice(prev_h);
        v.extend_from_slice(&subspace_number.to_be_bytes());
        Keccak256::digest(&v)
    };
    let search_subspace_seed = u64::from_be_bytes(
        encoded_subspace_number_hash_input[0..8]
            .try_into()
            .map_err(|_| MinerError::InvalidHashLength)?,
    );

    let search_subspace_start = search_subspace_seed % subspace_actual_size;

    let search_subspace_byte_seed_hash_input = Keccak256::digest(h0);
    let search_subspace_byte_seed = u64::from_be_bytes(
        search_subspace_byte_seed_hash_input[0..8]
            .try_into()
            .map_err(|_| MinerError::InvalidHashLength)?,
    );

    let search_subspace_byte = search_subspace_byte_seed % search_subspace_size;

    let absolute_subspace_start = subspace_start;
    let recall_byte = absolute_subspace_start.saturating_add(
        (search_subspace_start.saturating_add(search_subspace_byte)) % subspace_actual_size,
    );
    eprintln!("DEBUG: pick_recall_byte - Final recall_byte: {}", recall_byte);

    Ok(recall_byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // A basic test setup for Storage
    fn setup_test_storage(name: &str) -> Storage {
        let mut path = PathBuf::from("test_miner_storage");
        path.push(name);
        let _ = std::fs::remove_dir_all(&path);
        Storage::open(&path).expect("Failed to open test storage")
    }

    // Helper to create a dummy Packet
    fn create_dummy_packet(id_val: u8) -> Packet {
        let mut id_bytes = [0; 32];
        id_bytes[0] = id_val;
        Packet {
            id: id_bytes.into(),
            content: keyi_core::Content {
                creation: vec![id_val],
                lac: ciborium::Value::Bytes(vec![0]),
                parents: vec![],
                signer: format!("0x{:x}", id_val),
            },
            signature: vec![id_val],
        }
    }

    #[test]
    fn test_mine_block_skeleton() {
        let test_name = "test_mine_block_skeleton";
        let mut storage = setup_test_storage(test_name);

        let dummy_packet_a = create_dummy_packet(1);
        let dummy_packet_b = create_dummy_packet(2);
        storage.insert_packet(&dummy_packet_a).unwrap();
        storage.insert_packet(&dummy_packet_b).unwrap();

        let previous_block_header = BlockHeader {
            previous_block_id: [0; 32].into(),
            merkle_root: [0; 32],
            timestamp: 0,
            nonce: 0,
            spora_proof: [0; 32],
            difficulty: [0xFF; 32], // Very easy difficulty for testing
            height: 0,
        };

        // Initialize Miner
        eprintln!("DEBUG: tests::test_mine_block_skeleton - Initializing Miner...");
        let flags = RandomXFlag::default();
        let key = [0; 32]; // Use a fixed key for RandomX for reproducibility in tests
        let miner = Miner::new(flags, &key).expect("Failed to create miner");
        eprintln!("DEBUG: tests::test_mine_block_skeleton - Miner initialized.");
        
        let options = MineBlockOptions {
            previous_block_header: &previous_block_header,
            packets: &[dummy_packet_a.clone(), dummy_packet_b.clone()],
            storage: &mut storage,
            difficulty: previous_block_header.difficulty,
        };

        eprintln!("DEBUG: tests::test_mine_block_skeleton - Starting mine_block...");
        let result = miner.mine_block(options);
        eprintln!("DEBUG: tests::test_mine_block_skeleton - mine_block finished.");
        
        let _ = std::fs::remove_dir_all(&PathBuf::from("test_miner_storage").join(test_name));

        assert!(result.is_ok(), "Mining failed: {:?}", result.err());
        let block = result.unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.packet_ids.len(), 2);
    }
}