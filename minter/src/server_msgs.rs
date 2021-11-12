use crate::contract::BLOCK_SIZE;
use crate::msg::ViewerInfo;
use cosmwasm_std::HumanAddr;
use secret_toolkit::utils::{HandleCallback, Query};
use serde::{Deserialize, Serialize};

/// the svg server's handle messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerHandleMsg {
    /// allow a minter to add genes to prevent future duplicates
    AddGenes { genes: Vec<Vec<u8>> },
}

impl HandleCallback for ServerHandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// the svg server's query messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerQueryMsg {
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
}

impl Query for ServerQueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// genetic image information
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct GeneInfo {
    /// image at time of minting
    pub current_image: Vec<u8>,
    /// complete genetic image
    pub genetic_image: Vec<u8>,
    /// image used for uniqueness checks
    pub unique_check: Vec<u8>,
}

/// list of new genes
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct NewGenes {
    pub genes: Vec<GeneInfo>,
    
// TODO remove this
pub collisions: u16,    
    
    



}

/// wrapper to deserialize NewGenes responses
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct NewGenesResponse {
    pub new_genes: NewGenes,
}
