use serde::{Deserialize, Serialize};
use crate::metadata::Metadata;

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
/// storage key for the category count
pub const NUM_CATS_KEY: &[u8] = b"numcat";
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
    /// randomization weight table for jawed
    pub jawed_weights: Vec<u16>,
    /// randomization weight table for jawless
    pub jawless_weights: Option<Vec<u16>>,
}

/// category variant
#[derive(Serialize, Deserialize)]
pub struct Variant {
    /// name
    pub name: String,
    /// svg string if name is not `None`
    pub svg: Option<String>,
}

/// the metadata common to all NFTs
#[derive(Serialize, Deserialize)]
pub struct CommonMetadata {
    /// common public metadata
    pub public: Option<Metadata>,
    /// common privae metadata
    pub private: Option<Metadata>,
}
