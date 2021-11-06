use crate::contract_info::{ContractInfo, StoreContractInfo};
use crate::snip721::{
    DisplayRoyaltyInfo, Metadata, MintersResponse, RoyaltyInfo, RoyaltyInfoResponse,
    RoyaltyInfoWrapper, Snip721QueryMsg, StoredRoyaltyInfo, ViewerInfo,
};
use crate::state::PREFIX_CONTRACT;
use crate::storage::may_load;
use cosmwasm_std::{Api, Extern, Querier, StdError, StdResult, Storage};
use cosmwasm_storage::ReadonlyPrefixedStorage;
use schemars::JsonSchema;
use secret_toolkit::utils::Query;
use serde::{Deserialize, Serialize};

/// nft info used to mint clones
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct Template {
    /// identifier for this template
    pub name: String,
    /// optional public metadata that can be seen by everyone
    pub public_metadata: Option<Metadata>,
    /// optional private metadata that can only be seen by the owner and whitelist
    pub private_metadata: Option<Metadata>,
    /// optional royalty information for this token
    pub royalty_info: Option<RoyaltyInfo>,
    /// optional limit to how many clones will be minted for the first mint run
    pub minting_limit: Option<u32>,
    /// optional nft contract this template should use for minting
    pub nft_contract: Option<ContractInfo>,
}

/// displayable template info
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct TemplateInfo {
    /// identifier for this template
    pub name: String,
    /// optional public metadata that can be seen by everyone
    pub public_metadata: Option<Metadata>,
    /// optional private metadata that can only be seen by the owner and whitelist.
    /// This will only be displayed if an admin is querying
    pub private_metadata: Option<Metadata>,
    /// optional royalty information for this template
    pub royalty_info_of_template: Option<RoyaltyInfo>,
    /// if there is no royalty information for the template, the optional default royalty
    /// information of the snip721 contract
    pub default_royalties_of_nft_contract: Option<DisplayRoyaltyInfo>,
    /// mint run number
    pub mint_run: u32,
    /// next serial number to use
    pub next_serial: u32,
    /// optional limit to how many clones will be minted for this nft in this mint run
    pub minting_limit: Option<u32>,
    /// nft contract this template should use for minting
    pub nft_contract: ContractInfo,
    /// true if the minting contract is authorized to mint with this nft contract
    pub minting_authorized: bool,
}

/// stored nft info used to mint clones
#[derive(Serialize, Deserialize, Debug)]
pub struct StoredTemplate {
    /// identifier for this template
    pub name: String,
    /// optional public metadata that can be seen by everyone
    pub public_metadata: Option<Metadata>,
    /// optional private metadata that can only be seen by the owner and whitelist
    pub private_metadata: Option<Metadata>,
    /// optional royalty information for this token
    pub royalty_info: Option<StoredRoyaltyInfo>,
    /// mint run number
    pub mint_run: u32,
    /// next serial number to use
    pub next_serial: u32,
    /// optional limit to how many clones will be minted for this nft in this mint run
    pub minting_limit: Option<u32>,
    /// nft contract index
    pub nft_contract_idx: u16,
}

impl StoredTemplate {
    /// Returns StdResult<TemplateInfo> from converting a StoredTemplate to a TemplateInfo
    ///
    ///
    /// # Arguments
    ///
    /// * `deps` - reference to Extern containing all the contract's external dependencies
    /// * `cache` - cache of nft contract information
    /// * `viewer` - this contract's address and viewing key
    pub fn into_humanized<S: Storage, A: Api, Q: Querier>(
        self,
        deps: &Extern<S, A, Q>,
        cache: &mut Vec<MintAuthCache>,
        viewer: ViewerInfo,
    ) -> StdResult<TemplateInfo> {
        // if already saw this nft contract, pull the info from the cache
        let contr_info = if let Some(inf) = cache.iter().find(|c| c.index == self.nft_contract_idx)
        {
            inf.clone()
        // unseen nft contract
        } else {
            let contr_store = ReadonlyPrefixedStorage::new(PREFIX_CONTRACT, &deps.storage);
            let raw: StoreContractInfo =
                may_load(&contr_store, &self.nft_contract_idx.to_le_bytes())?
                    .ok_or_else(|| StdError::generic_err("NFT contract info storage is corrupt"))?;
            let nft_contract = raw.into_humanized(&deps.api)?;
            // check if this contract has minting authority
            let minters_query_msg = Snip721QueryMsg::Minters {};
            let minters_resp: MintersResponse = minters_query_msg.query(
                &deps.querier,
                nft_contract.code_hash.clone(),
                nft_contract.address.clone(),
            )?;
            let minting_authorized = minters_resp.minters.minters.contains(&viewer.address);
            // get default royalty info
            let def_query_msg = Snip721QueryMsg::RoyaltyInfo {
                viewer: Some(viewer),
            };
            let resp: StdResult<RoyaltyInfoWrapper> = def_query_msg.query(
                &deps.querier,
                nft_contract.code_hash.clone(),
                nft_contract.address.clone(),
            );
            let default = resp.unwrap_or(RoyaltyInfoWrapper {
                royalty_info: RoyaltyInfoResponse { royalty_info: None },
            });
            let inf = MintAuthCache {
                index: self.nft_contract_idx,
                contract_info: nft_contract,
                minting_authorized,
                default_royalty: default.royalty_info.royalty_info,
            };
            cache.push(inf.clone());
            inf
        };
        let default_royalties_of_nft_contract = if self.royalty_info.is_none() {
            contr_info.default_royalty
        } else {
            None
        };
        Ok(TemplateInfo {
            name: self.name,
            public_metadata: self.public_metadata,
            private_metadata: self.private_metadata,
            royalty_info_of_template: self
                .royalty_info
                .map(|r| r.get_humanized(&deps.api))
                .transpose()?,
            default_royalties_of_nft_contract,
            mint_run: self.mint_run,
            next_serial: self.next_serial,
            minting_limit: self.minting_limit,
            nft_contract: contr_info.contract_info,
            minting_authorized: contr_info.minting_authorized,
        })
    }
}

#[derive(Clone)]
// minting authority cache entry
pub struct MintAuthCache {
    // nft contract index
    pub index: u16,
    // nft contract info
    pub contract_info: ContractInfo,
    // true if minting contract is authorized to mint on the nft contract,
    pub minting_authorized: bool,
    // default royalty info of the nft contract
    pub default_royalty: Option<DisplayRoyaltyInfo>,
}
