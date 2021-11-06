use crate::contract::BLOCK_SIZE;
use cosmwasm_std::{Api, CanonicalAddr, HumanAddr, StdResult};
use schemars::JsonSchema;
use secret_toolkit::utils::{HandleCallback, Query};
use serde::{Deserialize, Serialize};

/// data for a single royalty
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Royalty {
    /// address to send royalties to
    pub recipient: HumanAddr,
    /// royalty rate
    pub rate: u16,
}

impl Royalty {
    /// Returns StdResult<StoredRoyalty> from creating a StoredRoyalty from a
    /// Royalty
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn get_stored<A: Api>(&self, api: &A) -> StdResult<StoredRoyalty> {
        Ok(StoredRoyalty {
            recipient: api.canonical_address(&self.recipient)?,
            rate: self.rate,
        })
    }
}

/// all royalty information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct RoyaltyInfo {
    /// decimal places in royalty rates
    pub decimal_places_in_rates: u8,
    /// list of royalties
    pub royalties: Vec<Royalty>,
}

impl RoyaltyInfo {
    /// Returns StdResult<StoredRoyaltyInfo> from creating a StoredRoyaltyInfo from a
    /// RoyaltyInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn get_stored<A: Api>(&self, api: &A) -> StdResult<StoredRoyaltyInfo> {
        Ok(StoredRoyaltyInfo {
            decimal_places_in_rates: self.decimal_places_in_rates,
            royalties: self
                .royalties
                .iter()
                .map(|r| r.get_stored(api))
                .collect::<StdResult<Vec<StoredRoyalty>>>()?,
        })
    }
}

/// data for storing a single royalty
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoredRoyalty {
    /// address to send royalties to
    pub recipient: CanonicalAddr,
    /// royalty rate
    pub rate: u16,
}

impl StoredRoyalty {
    /// Returns StdResult<DisplayRoyalty> from creating a DisplayRoyalty from a StoredRoyalty
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    /// * `hide_addr` - true if the address should be kept hidden
    pub fn to_display<A: Api>(&self, api: &A, hide_addr: bool) -> StdResult<DisplayRoyalty> {
        let recipient = if hide_addr {
            None
        } else {
            Some(api.human_address(&self.recipient)?)
        };
        Ok(DisplayRoyalty {
            recipient,
            rate: self.rate,
        })
    }

    /// Returns StdResult<Royalty> from creating a displayable Royalty from
    /// a StoredRoyalty
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn get_humanized<A: Api>(&self, api: &A) -> StdResult<Royalty> {
        Ok(Royalty {
            recipient: api.human_address(&self.recipient)?,
            rate: self.rate,
        })
    }
}

/// all stored royalty information
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoredRoyaltyInfo {
    /// decimal places in royalty rates
    pub decimal_places_in_rates: u8,
    /// list of royalties
    pub royalties: Vec<StoredRoyalty>,
}

impl StoredRoyaltyInfo {
    /// Returns StdResult<DisplayRoyaltyInfo> from creating a DisplayRoyaltyInfo from a StoredRoyaltyInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    /// * `hide_addr` - true if the address should be kept hidden
    pub fn to_display<A: Api>(&self, api: &A, hide_addr: bool) -> StdResult<DisplayRoyaltyInfo> {
        Ok(DisplayRoyaltyInfo {
            decimal_places_in_rates: self.decimal_places_in_rates,
            royalties: self
                .royalties
                .iter()
                .map(|r| r.to_display(api, hide_addr))
                .collect::<StdResult<Vec<DisplayRoyalty>>>()?,
        })
    }

    /// Returns StdResult<RoyaltyInfo> from creating a displayable RoyaltyInfo from
    /// a StoredRoyaltyInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn get_humanized<A: Api>(&self, api: &A) -> StdResult<RoyaltyInfo> {
        Ok(RoyaltyInfo {
            decimal_places_in_rates: self.decimal_places_in_rates,
            royalties: self
                .royalties
                .iter()
                .map(|r| r.get_humanized(api))
                .collect::<StdResult<Vec<Royalty>>>()?,
        })
    }
}

/// display for a single royalty
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct DisplayRoyalty {
    /// address to send royalties to.  Can be None to keep addresses private
    pub recipient: Option<HumanAddr>,
    /// royalty rate
    pub rate: u16,
}

/// display all royalty information
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct DisplayRoyaltyInfo {
    /// decimal places in royalty rates
    pub decimal_places_in_rates: u8,
    /// list of royalties
    pub royalties: Vec<DisplayRoyalty>,
}

/// information about the minting of the NFT
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct MintRunInfo {
    /// optional address of the SNIP-721 contract creator
    pub collection_creator: Option<HumanAddr>,
    /// address of this minting contract as the NFT's creator
    pub token_creator: HumanAddr,
    /// optional time of minting (in seconds since 01/01/1970)
    pub time_of_minting: Option<u64>,
    /// number of the mint run this token was minted in.  This is
    /// used to serialize identical NFTs
    pub mint_run: u32,
    /// serial number in this mint run.  This is used to serialize
    /// identical NFTs
    pub serial_number: u32,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}

/// Serial number to give an NFT when minting
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct SerialNumber {
    /// number of the mint run this token will be minted in.  This is
    /// used to serialize identical NFTs
    pub mint_run: u32,
    /// serial number (in this mint run).  This is used to serialize
    /// identical NFTs
    pub serial_number: u32,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}

/// snip721 handle msgs.  When the RoyaltyInfo and MintRunInfo gets added to the toolkit,
/// this won't be needed
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721HandleMsg {
    /// Mint multiple tokens
    BatchMintNft {
        /// list of mint operations to perform
        mints: Vec<Mint>,
    },
    /// set viewing key
    SetViewingKey {
        /// desired viewing key
        key: String,
    },
}

impl HandleCallback for Snip721HandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// token mint info used when doing a BatchMint
#[derive(Serialize)]
pub struct Mint {
    /// owner addres
    pub owner: HumanAddr,
    /// optional public metadata that can be seen by everyone
    pub public_metadata: Option<Metadata>,
    /// optional private metadata that can only be seen by owner and whitelist
    pub private_metadata: Option<Metadata>,
    /// serial number for this token
    pub serial_number: SerialNumber,
    /// optional royalty info for this token
    pub royalty_info: Option<RoyaltyInfo>,
    /// memo for the tx
    pub memo: String,
}

/// snip721 query msgs
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721QueryMsg {
    /// display the contract's creator
    ContractCreator {},
    /// display the default royalty info that is used whenever any token is minted without
    /// specifying its own royalty information
    RoyaltyInfo {
        /// optional address and key requesting to view the royalty information
        viewer: Option<ViewerInfo>,
    },
    /// display the list of authorized minters
    Minters {},
}

impl Query for Snip721QueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

/// Snip721 ContractCreator query response
#[derive(Deserialize)]
pub struct Snip721ContractCreator {
    /// optionally display the Snip721 contract's creator
    pub creator: Option<HumanAddr>,
}

/// wrapper used to deserialize the snip721 ContractCreator query
#[derive(Deserialize)]
pub struct Snip721ContractCreatorResponse {
    pub contract_creator: Snip721ContractCreator,
}

/// custom Snip721 RoyaltyInfo query response
#[derive(Deserialize)]
pub struct RoyaltyInfoResponse {
    /// nft contract's default royalty info if set
    pub royalty_info: Option<DisplayRoyaltyInfo>,
}

/// wrapper used to deserialize the snip721 RoyaltyInfo query
#[derive(Deserialize)]
pub struct RoyaltyInfoWrapper {
    pub royalty_info: RoyaltyInfoResponse,
}

/// Snip721 Minters query response
#[derive(Deserialize)]
pub struct Minters {
    /// list of authorized minting addresses
    pub minters: Vec<HumanAddr>,
}

/// wrapper used to deserialize the snip721 Minters query
#[derive(Deserialize)]
pub struct MintersResponse {
    pub minters: Minters,
}

/// token metadata
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Metadata {
    /// optional uri for off-chain metadata.  This should be prefixed with `http://`, `https://`, `ipfs://`, or
    /// `ar://`
    pub token_uri: Option<String>,
    /// optional on-chain metadata
    pub extension: Option<Extension>,
}

/// metadata extension
/// You can add any metadata fields you need here.  These fields are based on
/// https://docs.opensea.io/docs/metadata-standards and are the metadata fields that
/// Stashh uses for robust NFT display.  Urls should be prefixed with `http://`, `https://`, `ipfs://`, or
/// `ar://`
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Extension {
    /// url to the image
    pub image: Option<String>,
    /// raw SVG image data (not recommended). Only use this if you're not including the image parameter
    pub image_data: Option<String>,
    /// url to allow users to view the item on your site
    pub external_url: Option<String>,
    /// item description
    pub description: Option<String>,
    /// name of the item
    pub name: Option<String>,
    /// item attributes
    pub attributes: Option<Vec<Trait>>,
    /// background color represented as a six-character hexadecimal without a pre-pended #
    pub background_color: Option<String>,
    /// url to a multimedia attachment
    pub animation_url: Option<String>,
    /// url to a YouTube video
    pub youtube_url: Option<String>,
    /// media files as specified on Stashh that allows for basic authenticatiion and decryption keys.
    /// Most of the above is used for bridging public eth NFT metadata easily, whereas `media` will be used
    /// when minting NFTs on Stashh
    pub media: Option<Vec<MediaFile>>,
    /// list of attributes whose types are public but whose values are private
    pub protected_attributes: Option<Vec<String>>,
}

/// attribute trait
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Trait {
    /// indicates how a trait should be displayed
    pub display_type: Option<String>,
    /// name of the trait
    pub trait_type: Option<String>,
    /// trait value
    pub value: String,
    /// optional max value for numerical traits
    pub max_value: Option<String>,
}

/// media file
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct MediaFile {
    /// file type
    /// Stashh currently uses: "image", "video", "audio", "text", "font", "application"
    pub file_type: Option<String>,
    /// file extension
    pub extension: Option<String>,
    /// authentication information
    pub authentication: Option<Authentication>,
    /// url to the file.  Urls should be prefixed with `http://`, `https://`, `ipfs://`, or `ar://`
    pub url: String,
}

/// media file authentication
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Authentication {
    /// either a decryption key for encrypted files or a password for basic authentication
    pub key: Option<String>,
    /// username used in basic authentication
    pub user: Option<String>,
}
