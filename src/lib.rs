// csd-swarm library surface — the content-swarm building blocks, exposed so integration tests
// (and future embedders) can use them. The binary (main.rs) wires these into a running node.
pub mod acquire;
pub mod chain;
pub mod gateway;
pub mod p2p;
pub mod store;
