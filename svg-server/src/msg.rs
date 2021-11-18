#![allow(clippy::large_enum_variant)]
use crate::metadata::Metadata;
use crate::state::{
    Category, StoredDependencies, Variant, PREFIX_CATEGORY, PREFIX_CATEGORY_MAP, PREFIX_VARIANT,
    PREFIX_VARIANT_MAP,
};
use crate::storage::may_load;
use cosmwasm_std::{HumanAddr, ReadonlyStorage, StdError, StdResult};
use cosmwasm_storage::ReadonlyPrefixedStorage;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// weight for jawed skulls
    pub jaw_weight: u16,
    /// weight for jawless skulls
    pub jawless_weight: u16,
    /// entropy used for prng seed
    pub entropy: String,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// Create a viewing key
    CreateViewingKey { entropy: String },
    /// Set a viewing key
    SetViewingKey {
        key: String,
        // optional padding can be used so message length doesn't betray key length
        padding: Option<String>,
    },
    /// allows an admin to add more admins
    AddAdmins {
        /// list of address to grant admin priveleges
        admins: Vec<HumanAddr>,
    },
    /// allows an admin to remove admin addresses
    RemoveAdmins {
        /// list of address to revoke admin priveleges from
        admins: Vec<HumanAddr>,
    },
    /// allows an admin to add more viewers
    AddViewers {
        /// list of new addresses with viewing priveleges
        viewers: Vec<HumanAddr>,
    },
    /// allows an admin to remove viewer addresses
    RemoveViewers {
        /// list of address to revoke viewing priveleges from
        viewers: Vec<HumanAddr>,
    },
    /// allows an admin to add minters
    AddMinters {
        /// list of new addresses with viewing priveleges
        minters: Vec<HumanAddr>,
    },
    /// allows an admin to remove minter addresses
    RemoveMinters {
        /// list of address to revoke viewing priveleges from
        minters: Vec<HumanAddr>,
    },
    /// add new trait categories.  This in not meant to be used after minting begins
    AddCategories { categories: Vec<CategoryInfo> },
    /// add new trait variants to existing categories
    AddVariants { variants: Vec<CategoryInfo> },
    /// change the name, forced variants, or weight tables for an existing trait category
    ModifyCategory {
        /// name of the trait category to modify
        name: String,
        /// optional new name for the trait category
        new_name: Option<String>,
        /// optional new forced variants
        forced_variants: Option<ForcedVariants>,
        /// optional new weight tables for the category
        weights: Option<Weights>,
    },
    /// modify existing trait variants
    ModifyVariants { modifications: Vec<VariantModInfo> },
    /// set the common metadata for the collection
    SetMetadata {
        /// common public metadata
        public_metadata: Option<Metadata>,
        /// common private metadata
        private_metadata: Option<Metadata>,
    },
    /// Sets the layer categories to skip when rolling and the weightings for jawed vs
    /// jawless skulls
    SetRollConfig {
        /// names of the layer categories to skip when rolling
        skip: Option<Vec<String>>,
        /// weight for jawed skulls
        jaw_weight: Option<u16>,
        /// weight for jawless skulls
        jawless_weight: Option<u16>,
    },
    /// add dependencies for traits that have multiple layers
    AddDependencies {
        /// new dependencies to add
        dependencies: Vec<Dependencies>,
    },
    /// remove dependecies from trait variants
    RemoveDependencies {
        /// dependencies to remove
        dependencies: Vec<Dependencies>,
    },
    /// modify dependencies of a trait variant
    ModifyDependencies {
        /// dependencies to modify
        dependencies: Vec<Dependencies>,
    },
    /// add launch trait variants that hide other trait variants
    AddHiders {
        /// new hiders to add
        hiders: Vec<Dependencies>,
    },
    /// remove launch trait variants that hide other trait variants
    RemoveHiders {
        /// hiders to remove
        hiders: Vec<Dependencies>,
    },
    /// modify launch trait variants that hide other trait variants
    ModifyHiders {
        /// hiders to modify
        hiders: Vec<Dependencies>,
    },
    /// allow a minter to add genes to prevent future duplicates
    AddGenes { genes: Vec<Vec<u8>> },
    /// disallow the use of a permit
    RevokePermit {
        /// name of the permit that is no longer valid
        permit_name: String,
    },
}

/// Responses from handle functions
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    /// response from creating a viewing key
    ViewingKey { key: String },
    /// response from adding/removing admins
    AdminsList {
        // current admins
        admins: Vec<HumanAddr>,
    },
    /// response from adding/removing viewers
    ViewersList {
        // current viewers
        viewers: Vec<HumanAddr>,
    },
    /// response from adding/removing minters
    MintersList {
        // current operators
        minters: Vec<HumanAddr>,
    },
    /// response from adding new trait categories
    AddCategories {
        /// number of categories
        count: u8,
    },
    /// response from adding new trait variants
    AddVariants { status: String },
    /// response from modifying a trait category
    ModifyCategory { status: String },
    /// response from modifying existing trait variants
    ModifyVariants { status: String },
    /// response from setting common metadata
    SetMetadata { metadata: CommonMetadata },
    /// response from setting the roll config
    SetRollConfig { status: String },
    /// response from adding dependencies
    AddDependencies { status: String },
    /// response from removing dependencies
    RemoveDependencies { status: String },
    /// response from modifying dependencies
    ModifyDependencies { status: String },
    /// response from adding trait hiders
    AddHiders { status: String },
    /// response from removing trait hiders
    RemoveHiders { status: String },
    /// response from modifying trait hiders
    ModifyHiders { status: String },
    /// response from revoking a permit
    RevokePermit { status: String },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// lists the authorized addresses for this server
    AuthorizedAddresses {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays a trait category
    Category {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional category name to display
        name: Option<String>,
        /// optional category index to display
        index: Option<u8>,
        /// optional trait variant index to start at
        start_at: Option<u8>,
        /// max number of variants to display
        limit: Option<u8>,
        /// optionally true if svgs should be displayed.  Defaults to false
        display_svg: Option<bool>,
    },
    /// displays a layer variant
    Variant {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optionally display by the category and variant names
        by_name: Option<LayerId>,
        /// optionally display by the category and variant indices
        by_index: Option<StoredLayerId>,
        /// optionally true if svgs should be displayed.  Defaults to false
        display_svg: Option<bool>,
    },
    /// displays the common metadata
    CommonMetadata {
        /// optional address and viewing key of an admin, minter, or viewer
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the layer categories that get skipped during rolls and the weights of
    /// jawed vs jawless skulls
    RollConfig {
        /// optional address and viewing key of an admin, minter, or viewer
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the trait variants with dependencies (multiple layers)
    Dependencies {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional dependency index to start at
        start_at: Option<u16>,
        /// max number of dependencies to display
        limit: Option<u16>,
    },
    /// displays the launch trait variants that hide other trait variants
    Hiders {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional hider index to start at
        start_at: Option<u16>,
        /// max number of hiders to display
        limit: Option<u16>,
    },
    /// creates new and unique genetic images.  This can only be called by an authorized minter
    NewGenes {
        /// address and viewing key of a minting contract
        viewer: ViewerInfo,
        /// current block height
        height: u64,
        /// current block time
        time: u64,
        /// sender of the mint tx
        sender: HumanAddr,
        /// entropy for randomization
        entropy: String,
        /// the names of the background layer variants to use
        backgrounds: Vec<String>,
    },
    /// generates metadata from the input image vector
    TokenMetadata {
        /// optional address and viewing key of an admin, minter or viewer
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// image indices
        image: Vec<u8>,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// response listing the current authorized addresses
    AuthorizedAddresses {
        admins: Vec<HumanAddr>,
        minters: Vec<HumanAddr>,
        viewers: Vec<HumanAddr>,
    },
    /// display a trait category
    Category {
        /// number of categories
        category_count: u8,
        /// this category's index
        index: u8,
        /// trait category name
        name: String,
        /// forced variant for cyclops
        forced_cyclops: Option<String>,
        /// forced variant if jawless
        forced_jawless: Option<String>,
        /// number of variants in this category
        variant_count: u8,
        /// paginated variants for this category
        variants: Vec<VariantInfoPlus>,
    },
    /// display a layer variant
    Variant {
        /// the index of the category this variant belongs to
        category_index: u8,
        /// all the variant info
        info: VariantInfoPlus,
    },
    /// response for both CommonMetadata and TokenMetadata
    Metadata {
        public_metadata: Option<Metadata>,
        private_metadata: Option<Metadata>,
    },
    /// displays the layer categories that get skipped during rolls and the weights
    /// of jawed and jawless skulls
    RollConfig {
        /// number of categories
        category_count: u8,
        /// the categories that get skipped
        skip: Vec<String>,
        /// weight for jawed skulls
        jaw_weight: u16,
        /// weight for jawless skulls
        jawless_weight: u16,
    },
    /// displays the trait variants with dependencies (multiple layers)
    Dependencies {
        /// number of dependencies
        count: u16,
        dependencies: Vec<Dependencies>,
    },
    /// displays the launch trait variants that hide other trait variants
    Hiders {
        /// number of hiders
        count: u16,
        hiders: Vec<Dependencies>,
    },
    /// response from creating a new genetic images
    NewGenes {
        genes: Vec<GeneInfo>, // TODO remove this
        collisions: u16,
    },
}

/// genetic image information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct GeneInfo {
    /// image at time of minting
    pub current_image: Vec<u8>,
    /// complete genetic image
    pub genetic_image: Vec<u8>,
    /// image used for uniqueness checks
    pub unique_check: Vec<u8>,
}

/// trait variant information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct VariantInfo {
    /// trait variant name
    pub name: String,
    /// display name of the trait variant
    pub display_name: String,
    /// svg data if name is not `None`
    pub svg: Option<String>,
    /// randomization weight for this trait variant if skull has 2 eyes and a jaw
    pub normal_weight: u16,
    /// randomization weight for this variant if jawless
    pub jawless_weight: Option<u16>,
    /// randomization weight for cyclops
    pub cyclops_weight: Option<u16>,
}

/// trait variant information with its index and dependencies
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct VariantInfoPlus {
    /// index of variant
    pub index: u8,
    /// variant info
    pub variant_info: VariantInfo,
    /// layer variants it includes
    pub includes: Vec<LayerId>,
    /// trait variants it hides at launch
    pub hides_at_launch: Vec<LayerId>,
}

/// trait category information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct CategoryInfo {
    /// trait category name
    pub name: String,
    /// forced variant for cyclops
    pub forced_cyclops: Option<String>,
    /// forced variant if jawless
    pub forced_jawless: Option<String>,
    /// variants for this category
    pub variants: Vec<VariantInfo>,
}

/// info needed to call ModifyVariants
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct VariantModInfo {
    /// trait category name
    pub category: String,
    /// modifications to make to variants in this category
    pub modifications: Vec<VariantModification>,
}

/// info needed to modify trait variants
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct VariantModification {
    /// (old) trait variant name
    pub name: String,
    /// new variant data (may include a variant name change)
    pub modified_variant: VariantInfo,
}

/// randomization weights
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Weights {
    /// normal radomization weight table
    pub normal_weights: Vec<u16>,
    /// randomization weight table for jawless
    pub jawless_weights: Option<Vec<u16>>,
    /// randomization weight table for cyclops
    pub cyclops_weights: Option<Vec<u16>>,
}

/// forced variants
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ForcedVariants {
    /// forced variant for cyclops
    pub forced_cyclops: Option<String>,
    /// forced variant if jawless
    pub forced_jawless: Option<String>,
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

/// describes a trait that has multiple layers
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Dependencies {
    /// id of the layer variant that has dependencies
    pub id: LayerId,
    /// the other layers that are correlated to this variant
    pub correlated: Vec<LayerId>,
}

impl Dependencies {
    /// Returns StdResult<StoredDependencies> from creating a StoredDependencies from a Dependencies
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_stored<S: ReadonlyStorage>(&self, storage: &S) -> StdResult<StoredDependencies> {
        Ok(StoredDependencies {
            id: self.id.to_stored(storage)?,
            correlated: self
                .correlated
                .iter()
                .map(|l| l.to_stored(storage))
                .collect::<StdResult<Vec<StoredLayerId>>>()?,
        })
    }
}

/// identifies a layer
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct LayerId {
    /// the layer category name
    pub category: String,
    /// the variant name
    pub variant: String,
}

impl LayerId {
    /// Returns StdResult<StoredLayerId> from creating a StoredLayerId from a LayerId
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_stored<S: ReadonlyStorage>(&self, storage: &S) -> StdResult<StoredLayerId> {
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, storage);
        let cat_idx: u8 = may_load(&cat_map, self.category.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Category name:  {} does not exist", &self.category))
        })?;
        let var_map = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_VARIANT_MAP, &cat_idx.to_le_bytes()],
            storage,
        );
        let var_idx: u8 = may_load(&var_map, self.variant.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!(
                "Category {} does not have a variant named {}",
                &self.category, &self.variant
            ))
        })?;

        Ok(StoredLayerId {
            category: cat_idx,
            variant: var_idx,
        })
    }
}

/// identifies a layer
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct StoredLayerId {
    /// the layer category
    pub category: u8,
    pub variant: u8,
}

impl StoredLayerId {
    /// Returns StdResult<LayerId> from creating a LayerId from a StoredLayerId
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_display<S: ReadonlyStorage>(&self, storage: &S) -> StdResult<LayerId> {
        let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, storage);
        let cat_key = self.category.to_le_bytes();
        let cat: Category = may_load(&cat_store, &cat_key)?
            .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
        let var_store = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], storage);
        let var: Variant = may_load(&var_store, &self.variant.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
        Ok(LayerId {
            category: cat.name,
            variant: var.name,
        })
    }
}

/// the metadata common to all NFTs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CommonMetadata {
    /// common public metadata
    pub public: Option<Metadata>,
    /// common privae metadata
    pub private: Option<Metadata>,
}
