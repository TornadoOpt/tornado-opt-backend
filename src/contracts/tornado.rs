use super::{error::BlockchainError, utils::NormalProvider};
use alloy::{
    primitives::{Address, B256},
    sol,
};

sol!(
    #[sol(rpc)]
    Tornado,
    "abi/TornadoOptV1.json",
);

#[derive(Debug, Clone)]
pub struct TornadoContract {
    pub provider: NormalProvider,
    pub address: Address,
}

impl TornadoContract {
    pub fn new(provider: NormalProvider, address: Address) -> Self {
        Self { provider, address }
    }

    pub async fn get_hash_chain_root(&self) -> Result<B256, BlockchainError> {
        let tornado = Tornado::new(self.address, self.provider.clone());
        let root = tornado.hashChainRoot().call().await?;
        Ok(root)
    }

    // pub async fn get_deposit_data(&self, deposit_id: u64) -> Result<DepositData, BlockchainError> {
    //     let int1 = Int1::new(self.address, self.provider.clone());
    //     let data = int1.getDepositData(U256::from(deposit_id)).call().await?;
    //     let data = DepositData {
    //         deposit_hash: Bytes32::from_bytes_be(data.depositHash.as_ref()),
    //         sender: data.sender,
    //         is_rejected: data.isRejected,
    //     };
    //     Ok(data)
    // }

    // pub async fn get_withdrawal_nullifier_exists(
    //     &self,
    //     nullifier: Bytes32,
    // ) -> Result<bool, BlockchainError> {
    //     let int1 = Int1::new(self.address, self.provider.clone());
    //     let nullifier = convert_bytes32_to_b256(nullifier);
    //     let block_number = int1.nullifiers(nullifier).call().await?;
    //     Ok(!block_number.is_zero())
    // }

    // pub async fn get_last_processed_deposit_id(&self) -> Result<u64, BlockchainError> {
    //     let int1 = Int1::new(self.address, self.provider.clone());
    //     let id = int1.getLastProcessedDepositId().call().await?;
    //     Ok(id.to())
    // }

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

    // pub async fn cancel_deposit(
    //     &self,
    //     signer_private_key: B256,
    //     deposit_id: u64,
    //     recipient_salt_hash: Bytes32,
    //     token_index: u32,
    //     amount: U256,
    // ) -> Result<TxHash, BlockchainError> {
    //     let signer = get_provider_with_signer(&self.provider, signer_private_key);
    //     let contract = Int1::new(self.address, signer.clone());
    //     let deposit = Deposit {
    //         recipientSaltHash: convert_bytes32_to_b256(recipient_salt_hash),
    //         tokenIndex: token_index,
    //         amount,
    //     };
    //     let tx_request = contract
    //         .cancelDeposit(U256::from(deposit_id), deposit)
    //         .into_transaction_request();
    //     let tx_hash = send_transaction_with_gas_bump(
    //         &self.provider,
    //         signer,
    //         tx_request,
    //         "cancel_deposit",
    //         "depositor",
    //     )
    //     .await?;
    //     Ok(tx_hash)
    // }

    // pub async fn deposit_native_token(
    //     &self,
    //     signer_private_key: B256,
    //     recipient_salt_hash: Bytes32,
    //     value: U256,
    // ) -> Result<TxHash, BlockchainError> {
    //     let signer = get_provider_with_signer(&self.provider, signer_private_key);
    //     let contract = Int1::new(self.address, signer.clone());
    //     let tx_request = contract
    //         .depositNativeToken(convert_bytes32_to_b256(recipient_salt_hash))
    //         .value(value)
    //         .into_transaction_request();
    //     let tx_hash = send_transaction_with_gas_bump(
    //         &self.provider,
    //         signer,
    //         tx_request,
    //         "deposit_native_token",
    //         "depositor",
    //     )
    //     .await?;
    //     Ok(tx_hash)
    // }
}
