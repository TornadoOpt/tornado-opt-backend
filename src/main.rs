use rand::{SeedableRng as _, rngs::StdRng};
use tornado_opt_backend::{
    contracts::{tornado::TornadoContract, utils::get_provider},
    env::EnvVar,
    state::{State, observer::Observer},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    dotenvy::dotenv().ok();
    let env = envy::from_env::<EnvVar>().expect("Failed to load env var");
    let mut rng = StdRng::seed_from_u64(7);
    let provider = get_provider(&env.rpc_url)?;
    let contract = TornadoContract::new(provider, env.contract_address);
    let observer = Observer::new(contract, env.deployed_eth_block);
    let mut state = State::new(&mut rng, observer)?;

    log::info!("Setup completed");

    // sync and generate ivc proofs
    state.run().await?;

    // set checkpoint on chain
    state.set_checkpoint_on_chain(env.private_key).await?;

    Ok(())
}
