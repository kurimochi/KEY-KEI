use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use ciborium::{from_reader, into_writer};
use keyi_core::{ContentId, Packet};
use sled::Db;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Packet not found for the given ContentId")]
    NotFound,
    #[error("Attempted to access data out of bounds")]
    OutOfBounds,
    #[error("Sled DB error: {0}")]
    Db(#[from] sled::Error),
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Data serialization/deserialization error: {0}")]
    Codec(String),
}

/// A storage backend for KE<Y/I> that uses a simple append-only log for data
/// and a key-value store for the index. This is designed to support SPoRA.
pub struct Storage {
    index_db: Db,
    data_file: File,
    weave_size: u64,
}

impl Storage {
    /// Opens or creates a new storage at the given directory path.
    /// This will create two main files: `index.db` for the sled DB and `data.bin` for the append-only data log.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;

        let index_db_path = path.join("index.db");
        let data_file_path = path.join("data.bin");

        let index_db = sled::open(index_db_path)?;
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(data_file_path)?;

        let weave_size = data_file.metadata()?.len();

        Ok(Self {
            index_db,
            data_file,
            weave_size,
        })
    }

    /// Inserts a packet into the storage.
    /// The packet is serialized and appended to the `data.bin` file.
    /// An index entry mapping `ContentId` to `(offset, length)` is stored in `index.db`.
    pub fn insert_packet(&mut self, packet: &Packet) -> Result<(), StorageError> {
        // 1. Serialize the packet using CBOR.
        let mut packet_bytes = Vec::new();
        into_writer(packet, &mut packet_bytes).map_err(|e| StorageError::Codec(e.to_string()))?;

        // 2. The current weave_size is the offset for this new packet.
        let offset = self.weave_size;
        let length = packet_bytes.len() as u32;

        // 3. Append the serialized packet to the data file.
        self.data_file.seek(SeekFrom::Start(offset))?;
        self.data_file.write_all(&packet_bytes)?;

        // 4. Create and store the index entry using CBOR.
        let index_data = (offset, length);
        let mut index_bytes = Vec::new();
        into_writer(&index_data, &mut index_bytes)
            .map_err(|e| StorageError::Codec(e.to_string()))?;
        self.index_db
            .insert(Into::<[u8; 32]>::into(packet.id), index_bytes)?;

        // 5. Update the in-memory weave_size.
        self.weave_size += length as u64;

        // 6. Flush the index db to ensure durability.
        self.index_db.flush()?;

        Ok(())
    }

    /// Retrieves a packet from storage using its `ContentId`.
    pub fn get_packet(&mut self, id: ContentId) -> Result<Packet, StorageError> {
        // 1. Look up the index entry for the given ContentId.
        let index_bytes = self
            .index_db
            .get(Into::<[u8; 32]>::into(id))?
            .ok_or(StorageError::NotFound)?;

        // 2. Deserialize the index entry to get the offset and length.
        let (offset, length): (u64, u32) =
            from_reader(&index_bytes[..]).map_err(|e| StorageError::Codec(e.to_string()))?;

        // 3. Seek and read the packet data from the data file.
        self.data_file.seek(SeekFrom::Start(offset))?;
        let mut packet_bytes = vec![0; length as usize];
        self.data_file.read_exact(&mut packet_bytes)?;

        // 4. Deserialize the bytes back into a Packet.
        let packet: Packet =
            from_reader(&packet_bytes[..]).map_err(|e| StorageError::Codec(e.to_string()))?;

        Ok(packet)
    }

    /// Retrieves a raw chunk of data of a specific size from a given offset.
    /// This is the core function required for the SPoRA consensus mechanism.
    pub fn get_chunk(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, StorageError> {
        // 1. Check if the requested chunk is within the bounds of the weave.
        if offset.saturating_add(size as u64) > self.weave_size {
            return Err(StorageError::OutOfBounds);
        }

        // 2. Seek to the specified offset and read the chunk.
        self.data_file.seek(SeekFrom::Start(offset))?;
        let mut chunk_bytes = vec![0; size];
        self.data_file.read_exact(&mut chunk_bytes)?;

        Ok(chunk_bytes)
    }

    /// Returns the total size of the weave in bytes.
    pub fn get_weave_size(&self) -> u64 {
        self.weave_size
    }
}
