use alloy::primitives::{Address, B256};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct EnvVar {
    pub private_key: B256,
    pub rpc_url: String,
    pub deployed_eth_block: u64,
    pub contract_address: Address,
}
