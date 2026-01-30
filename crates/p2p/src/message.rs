use keyi_core::Packet;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub enum NetworkMessage {
    Packet(Packet),
}
