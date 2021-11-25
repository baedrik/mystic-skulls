use crate::contract::BLOCK_SIZE;
use crate::contract_info::ContractInfo;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use secret_toolkit::utils::{HandleCallback, Query};
use serde::{Deserialize, Serialize};

/// snip721 handle msgs.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721HandleMsg {
    /// set a token's ImageInfo.  This can only be called be an authorized minter
    SetImageInfo {
        /// id of the token whose image info should be updated
        token_id: String,
        /// the new image info
        image_info: ImageInfo,
    },
}

impl HandleCallback for Snip721HandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// snip721 query msgs
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721QueryMsg {
    /// display a token's ImageInfo
    ImageInfo {
        /// token whose image info to display
        token_id: String,
        /// address and viewing key of the querier
        viewer: ViewerInfo,
    },
    /// displays if the querier owns all the tokens in the list
    IsOwner {
        /// list of token IDs whose ownership is being checked
        token_ids: Vec<String>,
        /// address and viewing key of the owner
        viewer: ViewerInfo,
    },
    /// perform queries by passing permits instead of viewing keys
    WithPermit {
        /// permit used to verify querier identity
        permit: Permit,
        /// query to perform
        query: QueryWithPermit,
    },
}

impl Query for Snip721QueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

/// data that determines a token's appearance
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct ImageInfo {
    /// current image svg index array
    pub current: Vec<u8>,
    /// previous image svg index array
    pub previous: Vec<u8>,
    /// complete initial genetic image svg index array
    pub natural: Vec<u8>,
    /// optional svg server contract if not using the default
    pub svg_server: Option<HumanAddr>,
}

/// snip721 ImageInfo response
#[derive(Deserialize)]
pub struct ImageInfoResponse {
    /// owner of the token
    pub owner: HumanAddr,
    /// address and code hash of the svg server this token is using,
    pub server_used: ContractInfo,
    /// token's image info
    pub image_info: ImageInfo,
}

/// wrapper used to deserialize the snip721 ImageInfo query
#[derive(Deserialize)]
pub struct ImageInfoWrapper {
    pub image_info: ImageInfoResponse,
}

/// snip721 IsOwner response
#[derive(Deserialize)]
pub struct IsOwnerResponse {
    pub is_owner: bool,
}

/// wrapper used to deserialize the snip721 IsOwner query
#[derive(Deserialize)]
pub struct IsOwnerWrapper {
    pub is_owner: IsOwnerResponse,
}

/// queries using permits instead of viewing keys
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryWithPermit {
    /// displays if the querier owns all the tokens in the list
    IsOwner {
        /// list of token IDs whose ownership is being checked
        token_ids: Vec<String>,
    },
}
