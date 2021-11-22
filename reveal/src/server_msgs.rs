use crate::contract::BLOCK_SIZE;
use crate::snip721::ViewerInfo;
use secret_toolkit::utils::Query;
use serde::{Deserialize, Serialize};

/// the svg server's query messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerQueryMsg {
    /// display info that achemy/reveal contracts will need
    ServeAlchemy {
        /// address and viewing key of a reveal contract
        viewer: ViewerInfo,
    },
}

impl Query for ServerQueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// info needed for reveals
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ServeAlchemyResponse {
    /// categories that are skipped when rolling/revealing
    pub skip: Vec<u8>,
    /// variant display dependencies
    pub dependencies: Vec<StoredDependencies>,
    /// category names
    pub category_names: Vec<String>,
}

/// wrapper to deserialize ServeAlchemy responses
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ServeAlchemyWrapper {
    pub serve_alchemy: ServeAlchemyResponse,
}

/// identifies a layer
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoredLayerId {
    /// the layer category
    pub category: u8,
    pub variant: u8,
}

/// describes a trait that has multiple layers
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoredDependencies {
    /// id of the layer variant that has dependencies
    pub id: StoredLayerId,
    /// the other layers that are correlated to this variant
    pub correlated: Vec<StoredLayerId>,
}
