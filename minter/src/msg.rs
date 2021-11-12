use crate::contract_info::ContractInfo;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// code hash and address of the nft contract
    pub nft_contract: ContractInfo,
    /// code hash and address of the svg server contract
    pub svg_server: ContractInfo,
    /// address of the multisig
    pub multi_sig: HumanAddr,
    /// entropy used for prng seed
    pub entropy: String,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// Mint tokens
    Mint {
        /// list of backgrounds to mint
        backgrounds: Vec<String>,
        /// entropy used for rng
        entropy: String,
    },
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
    /// change the multi sig address
    NewMultiSig {
        /// new multi sig address
        address: HumanAddr,
    },
    /// halt/start minting
    SetMintStatus {
        /// true if minting should be halted
        halt: bool,
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
    /// response of setting a new multi sig address
    NewMultiSig {
        multi_sig: HumanAddr,
    },
    /// response from creating a viewing key
    ViewingKey {
        key: String,
    },
    /// response of changing the minting status
    SetMintStatus {
        /// true if minting has halted
        minting_has_halted: bool,
    },
    RevokePermit {
        status: String,
    },
    /// response of minting skulls
    Mint {
        skulls_minted: u16,

    
// TODO remove this
collisions: u16,    
    
    


    },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the minting status
    MintStatus {},
    /// display the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the mint counts
    MintCounts {},
    /// display the nft contract information
    NftContract {},
    /// display the svg server contract information
    SvgServer {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the multi sig address
    MultiSig {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
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
    /// displays the minting status
    MintStatus {
        /// true if minting has halted
        minting_has_halted: bool,
    },
    /// displays the mint counts
    MintCounts {
        /// total mint count
        total: u16,
        /// mint counts broken down by background variant
        by_background: Vec<BackgroundCount>,
    },
    /// displays the nft contract information
    NftContract { nft_contract: ContractInfo },
    /// displays the svg server information
    SvgServer { svg_server: ContractInfo },
    /// displays the multi sig address
    MultiSig { address: HumanAddr },
}

/// background count
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct BackgroundCount {
    /// name of the background variant
    pub background: String,
    /// number of tokens minted with this background
    pub count: u16,
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}
