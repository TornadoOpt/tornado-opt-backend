use alloy::providers::Provider as _;

use crate::contracts::tornado::{DepositEvent, TornadoContract};

pub struct Observer {
    pub contract: TornadoContract,
    pub deployed_eth_block: u64,
    pub deposit_events: Vec<DepositEvent>,
}

impl Observer {
    pub fn new(contract: TornadoContract, deployed_eth_block: u64) -> Self {
        Self {
            contract,
            deployed_eth_block,
            deposit_events: vec![],
        }
    }

    // todo: add scan pagination
    pub async fn scan(&mut self) -> anyhow::Result<()> {
        let latest_block = self.contract.provider.get_block_number().await?;
        let events = self
            .contract
            .get_deposit_events(self.deployed_eth_block, latest_block)
            .await?;
        self.deposit_events = events;
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
