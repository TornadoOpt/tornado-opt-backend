use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::{
        ProviderBuilder,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    rpc::client::RpcClient,
    signers::local::PrivateKeySigner,
    transports::{
        http::Http,
        layers::{FallbackLayer, RetryBackoffLayer},
    },
};
use reqwest::Url;
use tower::ServiceBuilder;

use crate::contracts::error::BlockchainError;

// Use simple nonce manager for the nonce filler because it's easier to handle nonce errors.
pub type JoinedRecommendedFillersWithSimpleNonce = JoinFill<
    alloy::providers::Identity,
    JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
>;

pub type NormalProvider =
    FillProvider<JoinedRecommendedFillersWithSimpleNonce, alloy::providers::RootProvider>;

pub type ProviderWithSigner = FillProvider<
    JoinFill<JoinedRecommendedFillersWithSimpleNonce, WalletFiller<EthereumWallet>>,
    alloy::providers::RootProvider,
>;

// alloy does not support fallback transport in WASM, so we use a provider without fallback transport in WASM.
pub fn get_provider(rpc_urls: &str) -> Result<NormalProvider, BlockchainError> {
    let retry_layer = RetryBackoffLayer::new(5, 1000, 100);
    let url: Url = rpc_urls
        .parse()
        .map_err(|e| BlockchainError::ParseError(format!("Failed to parse URL {rpc_urls}: {e}")))?;
    let client = RpcClient::builder().layer(retry_layer).http(url);
    let provider = ProviderBuilder::new().on_client(client);
    Ok(provider)
}

pub fn get_provider_with_fallback(rpc_urls: &[String]) -> Result<NormalProvider, BlockchainError> {
    let retry_layer = RetryBackoffLayer::new(5, 1000, 100);
    let transports = rpc_urls
        .iter()
        .map(|url| {
            let url: Url = url.parse().map_err(|e| {
                BlockchainError::ParseError(format!("Failed to parse URL {url}: {e}"))
            })?;
            Ok(Http::new(url))
        })
        .collect::<Result<Vec<_>, BlockchainError>>()?;
    let fallback_layer =
        FallbackLayer::default().with_active_transport_count(transports.len().try_into().unwrap());
    let transport = ServiceBuilder::new()
        .layer(fallback_layer)
        .service(transports);
    let client = RpcClient::builder()
        .layer(retry_layer)
        .transport(transport, false);
    let provider = ProviderBuilder::new().on_client(client);
    Ok(provider)
}

pub fn get_provider_with_signer(
    provider: &NormalProvider,
    private_key: B256,
) -> ProviderWithSigner {
    let signer = PrivateKeySigner::from_bytes(&private_key).unwrap();
    let wallet = EthereumWallet::new(signer);
    let wallet_filler = WalletFiller::new(wallet);
    provider.clone().join_with(wallet_filler)
}

pub fn get_address_from_private_key(private_key: B256) -> Address {
    let signer = PrivateKeySigner::from_bytes(&private_key).unwrap();
    signer.address()
}
