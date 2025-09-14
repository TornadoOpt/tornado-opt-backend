use alloy::primitives::B256;

use crate::state::State;

pub async fn checkpoint_operation(state: &mut State, private_key: B256) -> anyhow::Result<()> {
    // sync and generate ivc proofs
    state.run().await?;

    // set checkpoint on chain
    state.set_checkpoint_on_chain(private_key).await?;
    Ok(())
}
