use serde::{Deserialize, Serialize};

/// storage key for the admins list
pub const ADMINS_KEY: &[u8] = b"admin";
/// storage key for the viewers list
pub const VIEWERS_KEY: &[u8] = b"vwers";
/// storage key for the minters list
pub const MINTERS_KEY: &[u8] = b"mntrs";
/// storage key for this server's address
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// storage key for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// storage key for the roll config
pub const ROLL_CONF_KEY: &[u8] = b"roolcf";
/// storage key for the variant dependencies
pub const DEPENDENCIES_KEY: &[u8] = b"depend";
/// storage key for the variant that hide others
pub const HIDERS_KEY: &[u8] = b"hider";
/// storage key for the common metadata
pub const METADATA_KEY: &[u8] = b"metadata";
/// storage prefix for mapping a category name to its index
pub const PREFIX_CATEGORY_MAP: &[u8] = b"catemap";
/// storage prefix for mapping a variant name to its index
pub const PREFIX_VARIANT_MAP: &[u8] = b"vrntmap";
/// prefix for the storage of categories
pub const PREFIX_CATEGORY: &[u8] = b"category";
/// prefix for the storage of category variants
pub const PREFIX_VARIANT: &[u8] = b"variant";
/// prefix for storage of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkey";
/// prefix for storage of genes
pub const PREFIX_GENE: &[u8] = b"gene";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";

/// trait category
#[derive(Serialize, Deserialize)]
pub struct Category {
    /// name
    pub name: String,
    /// forced variant for cyclops
    pub forced_cyclops: Option<u8>,
    /// forced variant if jawless
    pub forced_jawless: Option<u8>,
    /// randomization weight table for normal skulls
    pub normal_weights: Vec<u16>,
    /// randomization weight table for jawless
    pub jawless_weights: Option<Vec<u16>>,
    /// randomization weight table for cyclops
    pub cyclops_weights: Option<Vec<u16>>,
}

/// category variant
#[derive(Serialize, Deserialize)]
pub struct Variant {
    /// name
    pub name: String,
    /// svg string if name is not `None`
    pub svg: Option<String>,
    /// display name
    pub display: String,
}

/// config values needed when rolling a new NFT
#[derive(Serialize, Deserialize)]
pub struct RollConfig {
    /// number of categories
    pub cat_cnt: u8,
    /// layer indices to skip when rolling
    pub skip: Vec<u8>,
    /// weights for drawing jawed vs jawless
    pub jaw_weights: Vec<u16>,
}
