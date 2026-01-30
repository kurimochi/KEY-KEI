use keyi_core::Packet;
use keyi_identity::{IdentityError, verify_packet_signature};
use libp2p::{PeerId, Swarm, Transport, futures::StreamExt, gossipsub, swarm::SwarmEvent};
use thiserror::Error;

use crate::{
    behaviour::{KeyiBehaviour, KeyiBehaviourEvent},
    message::NetworkMessage,
};

mod behaviour;
mod message;

pub async fn run_node() {
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let transport = libp2p::tcp::tokio::Transport::default()
        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(&local_key).unwrap())
        .multiplex(libp2p::yamux::Config::default())
        .boxed();

    let behaviour = KeyiBehaviour::new(&local_key).unwrap();

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(KeyiBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id,
                    message,
                })) => {
                    handle_gossip_message(swarm.behaviour_mut(), peer_id, message_id, message).await;
                }
                _ => {}
            }
        }
    }
}

async fn handle_gossip_message(
    behaviour: &mut KeyiBehaviour,
    source: PeerId,
    message_id: gossipsub::MessageId,
    message: gossipsub::Message,
) {
    let msg: NetworkMessage = match ciborium::from_reader(message.data.as_slice()) {
        Ok(m) => m,
        Err(_) => return,
    };

    match msg {
        NetworkMessage::Packet(packet) if message.topic.as_str() == "keyi/mempool" => {
            if validate_packet(&packet).is_ok() {
                behaviour.gossipsub.report_message_validation_result(
                    &message_id,
                    &source,
                    gossipsub::MessageAcceptance::Accept,
                );
            } else {
                behaviour.gossipsub.report_message_validation_result(
                    &message_id,
                    &source,
                    gossipsub::MessageAcceptance::Ignore,
                );
            }
        }
        _ => {}
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("CID mismatch detected")]
    InvalidCid,
    #[error("Identity verification failed: {0}")]
    Identity(#[from] IdentityError),
}

fn validate_packet(packet: &Packet) -> Result<(), ValidationError> {
    if packet.content.compute_id() != packet.id {
        return Err(ValidationError::InvalidCid);
    }
    verify_packet_signature(packet)?;

    // TODO: Add LaC verification in validate_inheritance after implementing keyi-storage

    Ok(())
}
