#![allow(clippy::large_enum_variant)]
use crate::contract_info::ContractInfo;
use crate::metadata::{Metadata};
use cosmwasm_std::{HumanAddr};
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
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
    /// allow a minter to add a gene to prevent a future duplicate
    AddGene { gene: Vec<u8> },
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
    SetMetadata { status: String },
    /// response from revoking a permit
    RevokePermit { status: String },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// lists the authorized addresses for this server
    AuthorizedAddresses{
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// view the info of one template
    Template {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// name of the template to view
        template_name: String,
    },
    /// view info of all templates
    AllTemplates {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page
        page: Option<u16>,
        /// optional max number of templates to display
        page_size: Option<u16>,
    },
    /// view all the nft contracts this minter can use
    AllNftContracts {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page
        page: Option<u16>,
        /// optional max number of templates to display
        page_size: Option<u16>,
    },
    /// display the public info of the next tokens that would be minted from the specified templates.
    /// If no template names are provided, display info from all templates
    PublicDescriptionOfNfts {
        /// templates whose info should be displayed
        template_names: Option<Vec<String>>,
        /// optional page
        page: Option<u16>,
        /// optional max number of templates to display
        page_size: Option<u16>,
    },
    /// display the public info of the next token to be minted from a specified
    /// option ID (template).  This is used for a universal minter query that
    /// listings will use
    NftListingDisplay {
        /// minting option that would be called upon purchase
        option_id: String,
    },
    // TODO
    // maybe add previous mint run quantities to template queries
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
}

/// trait variant information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct VariantInfo {
    /// trait variant name
    pub name: String,
    /// svg data if name is not `None`
    pub svg: Option<String>,
    /// randomization weight for this trait variant if jawed
    pub jawed_weight: u16,
    /// randomization weight for this variant if jawless
    pub jawless_weight: Option<u16>,
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
    /// randomization weight table for jawed
    pub jawed_weights: Vec<u16>,
    /// randomization weight table for jawless
    pub jawless_weights: Option<Vec<u16>>,
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
