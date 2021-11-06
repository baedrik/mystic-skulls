use crate::contract::BLOCK_SIZE;
use crate::contract_info::ContractInfo;
use cosmwasm_std::{HumanAddr, Uint128};
use secret_toolkit::utils::HandleCallback;
use serde::Serialize;

/// the factory's handle messages the minter will call
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactoryHandleMsg {
    /// creates a mint on demand listing
    CreateMinterListing {
        /// String label for the listing
        label: String,
        /// listing creator's address
        creator: HumanAddr,
        /// optional address to send proceeds to if not the creator
        payment_address: Option<HumanAddr>,
        /// optional number of NFTs to mint before the listing will auto-close.  If not
        /// specified, the listing will remain open until the creator closes it by
        /// calling CancelListing or the closes_at time is reached
        quantity_for_sale: Option<u32>,
        /// code hash and address of the minter contract
        minter_contract: ContractInfo,
        /// minting option to use when a purchase is made
        option_id: String,
        /// purchase contract code hash and address
        buy_contract: ContractInfo,
        /// true if purchasing token implements BatchSend
        batch_send: bool,
        /// listing price
        price: Uint128,
        /// timestamp after which the operator may close the listing.
        /// Timestamp is in seconds since epoch 01/01/1970
        closes_at: u64,
        /// Optional free-form description of the listing
        description: Option<String>,
        /// entropy used for random viewing key generation
        entropy: String,
        /// nft contract address that the token will be minted on
        nft_contract_address: HumanAddr,
        /// true if the minting contract implements RegisterListing to be notified of the listing address
        implements_register_listing: bool,
    },
}

impl HandleCallback for FactoryHandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}
