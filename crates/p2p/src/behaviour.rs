use libp2p::{
    gossipsub::{self, IdentTopic},
    identify,
    swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
pub struct KeyiBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
}

impl KeyiBehaviour {
    pub fn new(local_key: &libp2p::identity::Keypair) -> Result<Self, Box<dyn std::error::Error>> {
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .build()?;
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )?;

        let mempool_topic = IdentTopic::new("keyi/mempool");
        let spora_topic = IdentTopic::new("keyi/spora");
        gossipsub.subscribe(&mempool_topic)?;
        gossipsub.subscribe(&spora_topic)?;

        Ok(Self {
            gossipsub,
            identify: identify::Behaviour::new(identify::Config::new(
                "/keyi/1.0.0".to_string(),
                local_key.public(),
            )),
        })
    }
}
