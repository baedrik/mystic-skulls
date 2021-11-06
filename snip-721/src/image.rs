use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{Api, Storage, Extern, HumanAddr, StdResult, Querier};
use crate::registry::{Registry};
use crate::contract_info::{StoreContractInfo};
use crate::state::{PREFIX_SERVER_REGISTRY};

/// data that determines a token's appearance
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct ImageInfo {
    /// the random gene
    pub gene: u64,
    /// current image svg index array
    pub current: Vec<u8>,
    /// previous image svg index array
    pub previous: Vec<u8>,
    /// complete initial genetic image svg index array
    pub natural: Vec<u8>,
    /// optional svg server contract if not using the default
    pub svg_server: Option<HumanAddr>,
}

impl ImageInfo {
    /// Returns StdResult<StoredImageInfo> from converting an ImageInfo to a
    /// StoredImageInfo
    ///
    /// # Arguments
    ///
    /// * `deps` - reference to Extern containing all the contract's external dependencies
    pub fn into_stored<S: Storage, A: Api, Q: Querier>(self, deps: &Extern<S, A, Q>) -> StdResult<StoredImageInfo> {
        let svg_server = self.svg_server.map(|h| {
            let raw = deps.api.canonical_address(&h)?;
            let svr = Registry::<StoreContractInfo>::get_idx(
                &deps.storage,
                raw.as_slice(),
                PREFIX_SERVER_REGISTRY,
            )?;
            Ok(svr)
        }).transpose()?;
        Ok(StoredImageInfo {
            gene: self.gene,
            current: self.current,
            previous: self.previous,
            natural: self.natural,
            svg_server,
        })
    }
}

/// stored data that determines a token's appearance
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct StoredImageInfo {
    /// the random gene
    pub gene: u64,
    /// current image svg index array
    pub current: Vec<u8>,
    /// previous image svg index array
    pub previous: Vec<u8>,
    /// complete initial genetic image svg index array
    pub natural: Vec<u8>,
    /// optional svg server contract index if not using the default
    pub svg_server: Option<u16>,
}

impl StoredImageInfo {
    /// Returns StdResult<ImageInfo> from converting a StoredImageInfo to an
    /// ImageInfo
    ///
    /// # Arguments
    ///
    /// * `deps` - reference to Extern containing all the contract's external dependencies
    pub fn into_human<S: Storage, A: Api, Q: Querier>(self, deps: &Extern<S, A, Q>) -> StdResult<ImageInfo> {
        let svg_server = self.svg_server.map(|i| {
            let raw = Registry::<StoreContractInfo>::get_at(
                &deps.storage,
                i,
                PREFIX_SERVER_REGISTRY,
            )?;
            let svr = deps.api.human_address(&raw.address)?;
            Ok(svr)
        }).transpose()?;
        Ok(ImageInfo {
            gene: self.gene,
            current: self.current,
            previous: self.previous,
            natural: self.natural,
            svg_server,
        })
    }
}
