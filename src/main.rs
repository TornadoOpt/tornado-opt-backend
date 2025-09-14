use alloy::primitives::B256;
use clap::{Parser, command};
use rand::{SeedableRng as _, rngs::StdRng};
use tornado_opt_backend::{
    cli::{
        checkpoint::checkpoint_operation,
        deposit::{self, deposit_operation},
        withdrawal::withdrawal_operation,
    },
    contracts::{tornado::TornadoContract, utils::get_provider},
    env::EnvVar,
    state::{State, observer::Observer},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub enum CliCommand {
    Deposit {
        #[clap(long)]
        private_key: B256,
    },
    Withdrawal {
        #[clap(long)]
        private_key: B256,
        nullifier: B256,
        secret: B256,
    },
    Checkpoint {
        #[clap(long)]
        private_key: B256,
    },
}

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

    // parse command line arguments
    log::info!("Setup completed");

    let args = CliCommand::parse();
    match args {
        CliCommand::Deposit { private_key } => {
            deposit_operation(&mut state, private_key).await?;
            return Ok(());
        }
        CliCommand::Withdrawal {
            private_key,
            nullifier,
            secret,
        } => {
            withdrawal_operation(&mut state, nullifier, secret, private_key).await?;
            return Ok(());
        }
        CliCommand::Checkpoint { private_key } => {
            checkpoint_operation(&mut state, private_key).await?;
            return Ok(());
        }
    }
}
