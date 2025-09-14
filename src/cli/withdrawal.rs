use alloy::primitives::B256;

use crate::state::State;

pub async fn withdrawal_operation(
    _state: &mut State,
    _nullifier: B256,
    _secret: B256,
    _private_key: B256,
) -> anyhow::Result<()> {
    Ok(())
}
