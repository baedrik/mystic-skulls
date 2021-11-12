use cosmwasm_std::{
    to_binary, Api, BankMsg, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse, HandleResult,
    HumanAddr, InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError,
    StdResult, Storage, Uint128,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    snip20::set_viewing_key_msg,
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
};

use crate::msg::{
    BackgroundCount, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg, ViewerInfo,
};
use crate::rand::sha_256;
use crate::server_msgs::{NewGenesResponse, ServerHandleMsg, ServerQueryMsg};
use crate::snip721::{ImageInfo, Mint, SerialNumber, Snip721HandleMsg};
use crate::state::{
    Config, CONFIG_KEY, MY_ADDRESS_KEY, PREFIX_REVOKED_PERMITS, PREFIX_VIEW_KEY, PRNG_SEED_KEY,
};
use crate::storage::{load, may_load, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the minter contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    save(
        &mut deps.storage,
        MY_ADDRESS_KEY,
        &deps.api.canonical_address(&env.contract.address)?,
    )?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy.as_bytes()).as_bytes()).to_vec();
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    let vk = ViewingKey::new(&env, &prng_seed, msg.entropy.as_ref());
    let admins = vec![sender_raw];
    let config = Config {
        nft_contract: msg.nft_contract.get_store(&deps.api)?,
        svg_contract: msg.svg_server.get_store(&deps.api)?,
        halt: false,
        multi_sig: deps.api.canonical_address(&msg.multi_sig)?,
        mint_cnt: 0,
        backgd_cnts: Vec::new(),
        admins,
        viewing_key: vk.0,
    };
    save(&mut deps.storage, CONFIG_KEY, &config)?;

    Ok(InitResponse {
        messages: vec![
            set_viewing_key_msg(
                config.viewing_key.clone(),
                None,
                BLOCK_SIZE,
                msg.nft_contract.code_hash,
                msg.nft_contract.address,
            )?,
            set_viewing_key_msg(
                config.viewing_key,
                None,
                BLOCK_SIZE,
                msg.svg_server.code_hash,
                msg.svg_server.address,
            )?,
        ],
        log: vec![],
    })
}

///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::Mint {
            backgrounds,
            entropy,
        } => try_mint(deps, env, backgrounds, entropy),
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, &env.message.sender, key),
        HandleMsg::AddAdmins { admins } => try_add_admins(deps, &env.message.sender, &admins),
        HandleMsg::RemoveAdmins { admins } => try_remove_admins(deps, &env.message.sender, &admins),
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
        HandleMsg::NewMultiSig { address } => try_new_multi_sig(deps, &env.message.sender, address),
        HandleMsg::SetMintStatus { halt } => try_set_status(deps, &env.message.sender, halt),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// updates the minting status
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `backgrounds` - list of backgrounds to mint with
/// * `entropy` - entropy String for rng
fn try_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    backgrounds: Vec<String>,
    entropy: String,
) -> HandleResult {
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    if config.halt {
        return Err(StdError::generic_err(
            "The minter has been stopped.  No new tokens can be minted",
        ));
    }
    // limited to 20 mints
    let qty = backgrounds.len();
    if qty > 20 {
        return Err(StdError::generic_err(
            "Only 20 Mystic Skulls may be minted at once",
        ));
    }
    // stop minting at 10k
    if (config.mint_cnt as usize) + qty > 10000 {
        let remain = 10000 - config.mint_cnt;
        return Err(StdError::generic_err(format!(
            "Only {} Mystic Skulls are known to be left in the Secret Network graveyard",
            remain
        )));
    }
    // can't overflow if limited to 20, 1 SCRT is just testnet price
    let price = Uint128(1000000 * (qty as u128));
    if env.message.sent_funds.len() != 1
        || env.message.sent_funds[0].amount != price
        || env.message.sent_funds[0].denom != *"uscrt"
    {
        return Err(StdError::generic_err(format!(
            "You must pay exactly {} uscrt for {} Mystic Skulls",
            price, qty
        )));
    }
    let ser_num = (config.mint_cnt as u32) + 1;
    // update counts
    config.mint_cnt += qty as u16;
    for bg in backgrounds.iter() {
        if let Some(bgc) = config.backgd_cnts.iter_mut().find(|b| b.background == *bg) {
            bgc.count += 1;
        } else {
            config.backgd_cnts.push(BackgroundCount {
                background: bg.clone(),
                count: 1,
            });
        }
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    let viewer = ViewerInfo {
        address: env.contract.address.clone(),
        viewing_key: config.viewing_key.clone(),
    };
    // get the genes
    let svr_qry = ServerQueryMsg::NewGenes {
        viewer,
        height: env.block.height,
        time: env.block.time,
        sender: env.message.sender.clone(),
        entropy,
        backgrounds,
    };
    let server = config.svg_contract.into_humanized(&deps.api)?;
    let collection = config.nft_contract.into_humanized(&deps.api)?;
    let svr_resp: NewGenesResponse = svr_qry.query(
        &deps.querier,
        server.code_hash.clone(),
        server.address.clone(),
    )?;
    let mut genes: Vec<Vec<u8>> = Vec::new();
    let mut mints: Vec<Mint> = Vec::new();
    let mut serial_number = SerialNumber {
        mint_run: 1,
        serial_number: ser_num,
        quantity_minted_this_run: 10000,
    };
    for gene in svr_resp.new_genes.genes.into_iter() {
        mints.push(Mint {
            owner: env.message.sender.clone(),
            public_metadata: None,
            private_metadata: None,
            serial_number: serial_number.clone(),
            image_info: ImageInfo {
                current: gene.current_image.clone(),
                previous: gene.current_image,
                natural: gene.genetic_image,
                svg_server: None,
            },
        });
        serial_number.serial_number += 1;
        genes.push(gene.unique_check);
    }
    let mint_msg = Snip721HandleMsg::BatchMintNft { mints };
    let add_gene_msg = ServerHandleMsg::AddGenes { genes };
    let messages: Vec<CosmosMsg> = vec![
        mint_msg.to_cosmos_msg(collection.code_hash, collection.address, None)?,
        add_gene_msg.to_cosmos_msg(server.code_hash, server.address, None)?,
        CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address,
            to_address: deps.api.human_address(&config.multi_sig)?,
            amount: env.message.sent_funds,
        }),
    ];

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Mint {
            skulls_minted: qty as u16,

    
// TODO remove this
collisions: svr_resp.new_genes.collisions,    
    
    


        })?),
    })
}

/// Returns HandleResult
///
/// updates the minting status
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `halt` - true if minting should halt
fn try_set_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    halt: bool,
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    // only save it if the status is different
    if config.halt != halt {
        config.halt = halt;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMintStatus {
            minting_has_halted: halt,
        })?),
    })
}

/// Returns HandleResult
///
/// changes the multi sig address
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `address` - new multisig address
fn try_new_multi_sig<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    address: HumanAddr,
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let multi_raw = deps.api.canonical_address(&address)?;
    // only save it if the address is different
    if config.multi_sig != multi_raw {
        config.multi_sig = multi_raw;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::NewMultiSig {
            multi_sig: address,
        })?),
    })
}

/// Returns HandleResult
///
/// adds to the the admin list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `addrs_to_add` - list of addresses to add
fn try_add_admins<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    addrs_to_add: &[HumanAddr],
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = deps.api.canonical_address(addr)?;
        if !config.admins.contains(&raw) {
            config.admins.push(raw);
            save_it = true;
        }
    }
    // save list if it changed
    if save_it {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    let admins = config
        .admins
        .iter()
        .map(|a| deps.api.human_address(a))
        .collect::<StdResult<Vec<HumanAddr>>>()?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AdminsList { admins })?),
    })
}

/// Returns HandleResult
///
/// removes from the admin list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `addrs_to_remove` - list of addresses to remove
fn try_remove_admins<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    addrs_to_remove: &[HumanAddr],
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let old_len = config.admins.len();
    let rem_list = addrs_to_remove
        .iter()
        .map(|a| deps.api.canonical_address(a))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    config.admins.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    if old_len != config.admins.len() {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    let admins = config
        .admins
        .iter()
        .map(|a| deps.api.human_address(a))
        .collect::<StdResult<Vec<HumanAddr>>>()?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AdminsList { admins })?),
    })
}

/// Returns HandleResult
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `entropy` - string slice of the input String to be used as entropy in randomization
fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: &str,
) -> HandleResult {
    let prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let key = ViewingKey::new(env, &prng_seed, entropy.as_ref());
    let message_sender = &deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &key.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key: key.0 })?),
    })
}

/// Returns HandleResult
///
/// sets the viewing key to the input String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `key` - String to be used as the viewing key
fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    key: String,
) -> HandleResult {
    let vk = ViewingKey(key.clone());
    let message_sender = &deps.api.canonical_address(sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &vk.to_hashed())?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key })?),
    })
}

/// Returns HandleResult
///
/// revoke the ability to use a specified permit
///
/// # Arguments
///
/// * `storage` - mutable reference to the contract's storage
/// * `sender` - a reference to the message sender
/// * `permit_name` - string slice of the name of the permit to revoke
fn revoke_permit<S: Storage>(
    storage: &mut S,
    sender: &HumanAddr,
    permit_name: &str,
) -> HandleResult {
    RevokedPermits::revoke_permit(storage, PREFIX_REVOKED_PERMITS, sender, permit_name);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RevokePermit {
            status: "success".to_string(),
        })?),
    })
}

/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::MintStatus {} => query_status(&deps.storage),
        QueryMsg::Admins { viewer, permit } => query_admins(deps, viewer, permit),
        QueryMsg::MintCounts {} => query_counts(&deps.storage),
        QueryMsg::NftContract {} => query_nft_contract(deps),
        QueryMsg::SvgServer { viewer, permit } => query_server(deps, viewer, permit),
        QueryMsg::MultiSig { viewer, permit } => query_multi_sig(deps, viewer, permit),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying the multisig address
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_multi_sig<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (config, _) = check_admin(deps, viewer, permit)?;
    to_binary(&QueryAnswer::MultiSig {
        address: deps.api.human_address(&config.multi_sig)?,
    })
}

/// Returns QueryResult displaying the svg server contract information
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_server<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (config, _) = check_admin(deps, viewer, permit)?;
    to_binary(&QueryAnswer::SvgServer {
        svg_server: config.svg_contract.into_humanized(&deps.api)?,
    })
}

/// Returns QueryResult displaying the admin list
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_admins<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (config, _) = check_admin(deps, viewer, permit)?;
    to_binary(&QueryAnswer::Admins {
        admins: config
            .admins
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
    })
}

/// Returns QueryResult displaying the nft contract information
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
fn query_nft_contract<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::NftContract {
        nft_contract: config.nft_contract.into_humanized(&deps.api)?,
    })
}

/// Returns QueryResult displaying the minting status
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_status<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::MintStatus {
        minting_has_halted: config.halt,
    })
}

/// Returns QueryResult displaying the mint counts
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_counts<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::MintCounts {
        total: config.mint_cnt,
        by_background: config.backgd_cnts,
    })
}

/// Returns StdResult<(CanonicalAddr, Option<CanonicalAddr>)> from determining the querying address
/// (if possible) either from a Permit or a ViewerInfo.  Also returns this server's address if
/// a permit was supplied
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn get_querier<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> StdResult<(CanonicalAddr, Option<CanonicalAddr>)> {
    if let Some(pmt) = permit {
        // Validate permit content
        let me_raw: CanonicalAddr = may_load(&deps.storage, MY_ADDRESS_KEY)?
            .ok_or_else(|| StdError::generic_err("Minter contract address storage is corrupt"))?;
        let my_address = deps.api.human_address(&me_raw)?;
        let querier = deps.api.canonical_address(&validate(
            deps,
            PREFIX_REVOKED_PERMITS,
            &pmt,
            my_address,
        )?)?;
        if !pmt.check_permission(&secret_toolkit::permit::Permission::Owner) {
            return Err(StdError::generic_err(format!(
                "Owner permission is required for queries, got permissions {:?}",
                pmt.params.permissions
            )));
        }
        return Ok((querier, Some(me_raw)));
    }
    if let Some(vwr) = viewer {
        let raw = deps.api.canonical_address(&vwr.address)?;
        // load the address' key
        let key_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, &deps.storage);
        let load_key: [u8; VIEWING_KEY_SIZE] =
            may_load(&key_store, raw.as_slice())?.unwrap_or_else(|| [0u8; VIEWING_KEY_SIZE]);
        let input_key = ViewingKey(vwr.viewing_key);
        // if key matches
        if input_key.check_viewing_key(&load_key) {
            return Ok((raw, None));
        }
    }
    Err(StdError::unauthorized())
}

/// Returns StdResult<(Config, Option<CanonicalAddr>)> which is the Config and this
/// contract's address if it has been retrieved, and checks if the querier is an admin
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn check_admin<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> StdResult<(Config, Option<CanonicalAddr>)> {
    let (admin, my_addr) = get_querier(deps, viewer, permit)?;
    // only allow admins to do this
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    if !config.admins.contains(&admin) {
        return Err(StdError::unauthorized());
    }
    Ok((config, my_addr))
}
