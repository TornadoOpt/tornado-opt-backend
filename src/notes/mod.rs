use alloy::primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Note {
    pub nullifier: B256,
    pub secret: B256,
    pub commitment: B256,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_example() {
        assert_eq!(2 + 2, 4);
    }
}
