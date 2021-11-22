#![allow(clippy::large_enum_variant)]
use crate::contract_info::ContractInfo;
use crate::snip721::ViewerInfo;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// code hash and address of the nft contract
    pub nft_contract: ContractInfo,
    /// code hash and address of an svg server contract
    pub svg_server: ContractInfo,
    /// entropy used for prng seed
    pub entropy: String,
    /// cooldown period for random reveals
    pub random_cooldown: u64,
    /// cooldown period for targeted reveals
    pub target_cooldown: u64,
    /// cooldown period for revealing all
    pub all_cooldown: u64,
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
    /// halt/start revelation
    SetRevealStatus {
        /// true if revelation should be halted
        halt: bool,
    },
    /// set cooldown periods
    SetCooldowns {
        /// optional new cooldown period for random reveals
        random_cooldown: Option<u64>,
        /// optional new cooldown period for targeted reveals
        target_cooldown: Option<u64>,
        /// optional new cooldown period for revealing all
        all_cooldown: Option<u64>,
    },
    /// attempt to reveal a skull's trait(s)
    Reveal {
        /// token id of the skull
        token_id: String,
        /// type of reveal to attempt
        reveal_type: RevealType,
    },
    /// set the viewing key with an svg server contract
    SetKeyWithServer {
        /// svg server code hash and address
        svg_server: ContractInfo,
    },
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
    /// response of both AddAdmins and RemoveAdmins
    AdminsList {
        /// current admins
        admins: Vec<HumanAddr>,
    },
    /// response from creating a viewing key
    ViewingKey {
        key: String,
    },
    // response from setting a viewing key with an svg server
    SetKeyWithServer {
        status: String,
    },
    /// response of changing the revelation status
    SetRevealStatus {
        /// true if revelation has halted
        reveals_have_halted: bool,
    },
    RevokePermit {
        status: String,
    },
    /// response of attempting a reveal
    Reveal {
        /// the trait categories revealed
        categories_revealed: Vec<String>,
    },
    /// response from setting cooldown periods
    SetCooldowns {
        /// cooldown period for random reveals
        random_cooldown: u64,
        /// cooldown period for targeted reveals
        target_cooldown: u64,
        /// cooldown period for revealing all
        all_cooldown: u64,
    },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the revelation status
    RevealStatus {},
    /// display the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the nft contract information
    NftContract {},
    /// display the cooldown periods
    Cooldowns {},
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// displays the admins list
    Admins {
        /// current admin list
        admins: Vec<HumanAddr>,
    },
    /// displays the revelation status
    RevealStatus {
        /// true if revelation has halted
        reveals_have_halted: bool,
    },
    /// displays cooldown periods
    Cooldowns {
        /// cooldown period for random reveals
        random_cooldown: u64,
        /// cooldown period for targeted reveals
        target_cooldown: u64,
        /// cooldown period for revealing all
        all_cooldown: u64,
    },
    /// displays the nft contract information
    NftContract { nft_contract: ContractInfo },
}

/// types of reveal actions
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RevealType {
    /// reveal a random triat
    Random {
        /// entropy string for randomization
        entropy: String,
    },
    /// reveal a specific trait
    Targeted {
        /// trait category to reveal
        category: String,
    },
    /// reveal all traits
    All,
}
