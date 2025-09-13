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
    pub index: u64,
    pub commitment: B256,
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
        for (event, meta) in events {
            deposit_events.push(DepositEvent {
                index: todo!("get deposit index from event"),
                commitment: event.commitment,
            });
        }
        deposit_events.sort_by_key(|event| event.index);
        Ok(deposit_events)
    }

    pub async fn get_hash_chain_root(&self) -> Result<B256, BlockchainError> {
        let tornado = Tornado::new(self.address, self.provider.clone());
        let root = tornado.hashChainRoot().call().await?;
        Ok(root)
    }

    pub async fn set_checkpoint(
        &self,
        proof: Vec<u8>,
        hash_chain_root: B256,
        virtual_merkle_root: B256,
    ) -> Result<(), BlockchainError> {
        let signer = self.provider.clone(); // Assuming the provider has signing capabilities
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

    // pub async fn withdrawal(
    //     &self,
    //     signer_private_key: B256,
    //     pis: &SimpleWithdrawalPublicInputs,
    //     proof: Vec<u8>,
    // ) -> Result<TxHash, BlockchainError> {
    //     let signer = get_provider_with_signer(&self.provider, signer_private_key);
    //     let contract = Int1::new(self.address, signer.clone());
    //     let public_inputs = WithdrawalPublicInputs {
    //         depositRoot: convert_bytes32_to_b256(pis.deposit_root),
    //         nullifier: convert_bytes32_to_b256(pis.nullifier),
    //         recipient: convert_address_to_alloy(pis.recipient),
    //         tokenIndex: pis.token_index,
    //         amount: convert_u256_to_alloy(pis.amount),
    //     };
    //     let tx_request = contract
    //         .withdraw(public_inputs, proof.into())
    //         .into_transaction_request();
    //     let tx_hash = send_transaction_with_gas_bump(
    //         &self.provider,
    //         signer,
    //         tx_request,
    //         "withdrawal",
    //         "withdrawer",
    //     )
    //     .await?;
    //     Ok(tx_hash)
    // }
}
