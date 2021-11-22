use crate::contract_info::{ContractInfo, StoreContractInfo};
use crate::registry::Registry;
use crate::state::load;
use crate::state::{ServerInfo, PREFIX_SERVER_REGISTRY, SVG_INFO_KEY};
use cosmwasm_std::{Api, Extern, HumanAddr, Querier, StdResult, Storage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

impl ImageInfo {
    /// Returns StdResult<StoredImageInfo> from converting an ImageInfo to a
    /// StoredImageInfo
    ///
    /// # Arguments
    ///
    /// * `deps` - reference to Extern containing all the contract's external dependencies
    pub fn into_stored<S: Storage, A: Api, Q: Querier>(
        self,
        deps: &Extern<S, A, Q>,
    ) -> StdResult<StoredImageInfo> {
        let svg_server = self
            .svg_server
            .map(|h| {
                let raw = deps.api.canonical_address(&h)?;
                let svr = Registry::<StoreContractInfo>::get_idx(
                    &deps.storage,
                    raw.as_slice(),
                    PREFIX_SERVER_REGISTRY,
                )?;
                Ok(svr)
            })
            .transpose()?;
        Ok(StoredImageInfo {
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
    /// Returns StdResult<(ImageInfo, ContractInfo)> from converting a StoredImageInfo to an
    /// ImageInfo and providing the contract info of the server used
    ///
    /// # Arguments
    ///
    /// * `deps` - reference to Extern containing all the contract's external dependencies
    pub fn into_human<S: Storage, A: Api, Q: Querier>(
        self,
        deps: &Extern<S, A, Q>,
    ) -> StdResult<(ImageInfo, ContractInfo)> {
        let svr_idx = self.svg_server.as_ref().map_or_else(
            || {
                let svr_inf: ServerInfo = load(&deps.storage, SVG_INFO_KEY)?;
                Ok(svr_inf.default)
            },
            |i| Ok(*i),
        )?;
        let svr_raw =
            Registry::<StoreContractInfo>::get_at(&deps.storage, svr_idx, PREFIX_SERVER_REGISTRY)?;
        let svr_hum = svr_raw.into_humanized(&deps.api)?;
        let svg_server = self.svg_server.map(|_| svr_hum.address.clone());
        Ok((
            ImageInfo {
                current: self.current,
                previous: self.previous,
                natural: self.natural,
                svg_server,
            },
            svr_hum,
        ))
    }
}
