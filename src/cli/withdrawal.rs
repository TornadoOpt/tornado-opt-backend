use alloy::primitives::B256;

use crate::state::State;

pub async fn withdrawal_operation(
    state: &mut State,
    nullifier: B256,
    secret: B256,
    private_key: B256,
) -> anyhow::Result<()> {
    Ok(())
}
