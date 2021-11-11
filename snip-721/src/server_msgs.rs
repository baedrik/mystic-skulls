use crate::contract::BLOCK_SIZE;
use crate::msg::ViewerInfo;
use crate::token::Metadata;
use secret_toolkit::utils::Query;
use serde::{Deserialize, Serialize};

/// the svg server's query messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerQueryMsg {
    /// generates metadata from the input image vector
    TokenMetadata {
        /// address and viewing key of this token contract
        viewer: ViewerInfo,
        /// image indices
        image: Vec<u8>,
    },
}

impl Query for ServerQueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// public and private metadata returned from the TokenMetadata query
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TokenMetadata {
    pub public_metadata: Option<Metadata>,
    pub private_metadata: Option<Metadata>,
}

/// wrapper to deserialize TokenMetadata responses
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TokenMetadataResponse {
    pub metadata: TokenMetadata,
}
