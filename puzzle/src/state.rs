use cosmwasm_std::CanonicalAddr;
use serde::{Deserialize, Serialize};

use crate::msg::StoredWinner;

/// storage key for the config
pub const CONFIG_KEY: &[u8] = b"config";
/// storage key for this server's address
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// storage key for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// prefix for storage of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkeys";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";

/// minter state
#[derive(Serialize, Deserialize)]
pub struct Config {
    /// puzzle ids and keyphrases
    pub winners: Vec<StoredWinner>,
    /// list of admins
    pub admins: Vec<CanonicalAddr>,
}
