use crate::contracts::utils::get_provider_with_signer;

use super::{error::BlockchainError, utils::NormalProvider};
use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider as _,
    sol,
};

sol!(
    #[sol(rpc)]
    Tornado,
    "abi/TornadoOptV1.json",
);

#[derive(Debug, Clone)]
pub struct DepositEvent {
    pub commitment: B256,
    pub index: u64,
}

#[derive(Debug, Clone)]
pub struct TornadoContract {
    pub provider: NormalProvider,
    pub address: Address,
}

impl TornadoContract {
    pub fn new(provider: NormalProvider, address: Address) -> Self {
        Self { provider, address }
    }

    pub async fn get_deposit_events(
        &self,
        from_eth_block: u64,
        to_eth_block_number: u64,
    ) -> Result<Vec<DepositEvent>, BlockchainError> {
        let contract = Tornado::new(self.address, self.provider.clone());
        let events = contract
            .event_filter::<Tornado::Deposit>()
            .address(self.address)
            .from_block(from_eth_block)
            .to_block(to_eth_block_number)
            .query()
            .await?;
        let mut deposit_events = Vec::new();
        for (event, _meta) in events {
            deposit_events.push(DepositEvent {
                index: event.index.try_into().unwrap(),
                commitment: event.commitment,
            });
        }
        deposit_events.sort_by_key(|event| event.index);
        Ok(deposit_events)
    }

    pub async fn get_deposit_index(
        &self,
        commitment: B256,
    ) -> Result<Option<u64>, BlockchainError> {
        let contract = Tornado::new(self.address, self.provider.clone());
        let events = contract
            .event_filter::<Tornado::Deposit>()
            .address(self.address)
            .from_block(0)
            .topic1(commitment)
            .query()
            .await?;
        if events.is_empty() {
            Ok(None)
        } else {
            let (event, _meta) = &events[0];
            Ok(Some(event.index.try_into().unwrap()))
        }
    }

    pub async fn get_hash_chain_root(&self) -> Result<B256, BlockchainError> {
        let tornado = Tornado::new(self.address, self.provider.clone());
        let root = tornado.hashChainRoot().call().await?;
        Ok(root._0)
    }

    pub async fn get_denomination(&self) -> Result<alloy::primitives::U256, BlockchainError> {
        let tornado = Tornado::new(self.address, self.provider.clone());
        let denom = tornado.denomination().call().await?;
        Ok(denom._0)
    }

    pub async fn set_checkpoint(
        &self,
        signer_private_key: B256,
        proof: Vec<u8>,
        hash_chain_root: B256,
        virtual_merkle_root: B256,
    ) -> Result<(), BlockchainError> {
        let signer = get_provider_with_signer(&self.provider, signer_private_key);
        let contract = Tornado::new(self.address, signer.clone());
        let tx_request = contract
            .setCheckpoint(proof.into(), hash_chain_root, virtual_merkle_root)
            .into_transaction_request();
        let _tx_hash = signer.send_transaction(tx_request).await?;
        Ok(())
    }

    pub async fn deposit(
        &self,
        signer_private_key: B256,
        commitment: B256,
        amount: U256,
    ) -> Result<(), BlockchainError> {
        let signer = get_provider_with_signer(&self.provider, signer_private_key);
        let contract = Tornado::new(self.address, signer.clone());
        let tx_request = contract
            .deposit(commitment)
            .value(amount)
            .into_transaction_request();
        let _tx_hash = signer.send_transaction(tx_request).await?;
        Ok(())
    }

    pub async fn withdraw(
        &self,
        signer_private_key: B256,
        proof_w: Vec<u8>,
        nullifier_hash: B256,
        virtual_merkle_root: B256,
        recipient: Address,
    ) -> Result<(), BlockchainError> {
        let signer = get_provider_with_signer(&self.provider, signer_private_key);
        let contract = Tornado::new(self.address, signer.clone());
        let tx_request = contract
            .withdraw(
                proof_w.into(),
                nullifier_hash,
                virtual_merkle_root,
                recipient,
            )
            .into_transaction_request();
        let _tx_hash = signer.send_transaction(tx_request).await?;
        Ok(())
    }
}
