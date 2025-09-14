use alloy::primitives::B256;

use crate::state::State;

pub async fn deposit_operation(_state: &mut State, _private_key: B256) -> anyhow::Result<()> {
    Ok(())
}
