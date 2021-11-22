use cosmwasm_std::{
    to_binary, Api, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse, HandleResult, HumanAddr,
    InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use rand::seq::SliceRandom;
use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    snip20::set_viewing_key_msg,
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
};

use crate::msg::{HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg, RevealType};
use crate::rand::{extend_entropy, sha_256, Prng};
use crate::server_msgs::{
    ServeAlchemyResponse, ServeAlchemyWrapper, ServerQueryMsg, StoredDependencies, StoredLayerId,
};
use crate::snip721::{ImageInfo, ImageInfoWrapper, Snip721HandleMsg, Snip721QueryMsg, ViewerInfo};
use crate::state::{
    Config, CONFIG_KEY, MY_ADDRESS_KEY, PREFIX_REVOKED_PERMITS, PREFIX_TIMESTAMP, PREFIX_VIEW_KEY,
    PRNG_SEED_KEY,
};
use crate::storage::{load, may_load, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the reveal contract
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
        halt: false,
        admins,
        viewing_key: vk.0,
        random_cool: msg.random_cooldown,
        target_cool: msg.target_cooldown,
        all_cool: msg.all_cooldown,
    };
    save(&mut deps.storage, CONFIG_KEY, &config)?;

    Ok(InitResponse {
        messages: vec![set_viewing_key_msg(
            config.viewing_key.clone(),
            None,
            BLOCK_SIZE,
            msg.nft_contract.code_hash,
            msg.nft_contract.address,
        )?],
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
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, &env.message.sender, key),
        HandleMsg::AddAdmins { admins } => try_add_admins(deps, &env.message.sender, &admins),
        HandleMsg::RemoveAdmins { admins } => try_remove_admins(deps, &env.message.sender, &admins),
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
        HandleMsg::SetRevealStatus { halt } => try_set_status(deps, &env.message.sender, halt),
        HandleMsg::SetCooldowns {
            random_cooldown,
            target_cooldown,
            all_cooldown,
        } => try_set_cooldowns(
            deps,
            &env.message.sender,
            random_cooldown,
            target_cooldown,
            all_cooldown,
        ),
        HandleMsg::Reveal {
            token_id,
            reveal_type,
        } => try_reveal(deps, env, token_id, reveal_type),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// reveals token trait(s)
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `token_id` - ID of token being revealed
/// * `reveal_type` - type of reveal being requested
fn try_reveal<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    token_id: String,
    reveal_type: RevealType,
) -> HandleResult {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    if config.halt {
        return Err(StdError::generic_err("Reveals have been halted"));
    }
    // get and update the time of last reveal
    let mut time_store = PrefixedStorage::new(PREFIX_TIMESTAMP, &mut deps.storage);
    let token_key = token_id.as_bytes();
    let last_reveal: Option<u64> = may_load(&time_store, token_key)?;
    save(&mut time_store, token_key, &env.block.time)?;
    let me_raw: CanonicalAddr = may_load(&deps.storage, MY_ADDRESS_KEY)?
        .ok_or_else(|| StdError::generic_err("Reveal contract address storage is corrupt"))?;
    let address = deps.api.human_address(&me_raw)?;
    let viewer = ViewerInfo {
        address,
        viewing_key: config.viewing_key,
    };
    // get the token's image info
    let img_msg = Snip721QueryMsg::ImageInfo {
        token_id: token_id.clone(),
        viewer: viewer.clone(),
    };
    let collection = config.nft_contract.into_humanized(&deps.api)?;
    let img_wrap: ImageInfoWrapper = img_msg.query(
        &deps.querier,
        collection.code_hash.clone(),
        collection.address.clone(),
    )?;
    let mut image = img_wrap.image_info;
    // only let the token's owner reveal
    if env.message.sender != image.owner {
        return Err(StdError::unauthorized());
    }
    // get the svg server info
    let svr_msg = ServerQueryMsg::ServeAlchemy { viewer };
    let svr_wrap: ServeAlchemyWrapper = svr_msg.query(
        &deps.querier,
        image.server_used.code_hash,
        image.server_used.address,
    )?;
    image.image_info.previous = image.image_info.current.clone();
    let categories_revealed = match reveal_type {
        RevealType::Random { entropy } => random_reveal(
            &deps.storage,
            env,
            &mut image.image_info,
            svr_wrap.serve_alchemy,
            &entropy,
            config.random_cool,
            last_reveal,
        )?,
        RevealType::Targeted { category } => {
            target_reveal(
                env.block.time,
                &mut image.image_info,
                &svr_wrap.serve_alchemy,
                &category,
                config.target_cool,
                last_reveal,
            )?;
            vec![category]
        }
        RevealType::All {} => all_reveal(
            env.block.time,
            &mut image.image_info,
            svr_wrap.serve_alchemy.category_names,
            &svr_wrap.serve_alchemy.skip,
            config.all_cool,
            last_reveal,
        )?,
    };

    let set_img_msg = Snip721HandleMsg::SetImageInfo {
        token_id,
        image_info: image.image_info,
    };
    let messages: Vec<CosmosMsg> =
        vec![set_img_msg.to_cosmos_msg(collection.code_hash, collection.address, None)?];

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Reveal {
            categories_revealed,
        })?),
    })
}

/// Returns HandleResult
///
/// updates the revelation status
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
        data: Some(to_binary(&HandleAnswer::SetRevealStatus {
            reveals_have_halted: halt,
        })?),
    })
}

/// Returns HandleResult
///
/// updates the cooldown periods
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `random_cooldown` - optional new reveal random trait cooldown period in seconds
/// * `target_cooldown` - optional new reveal targeted trait cooldown period in seconds
/// * `all_cooldown` - optional new reveal all cooldown period in seconds
fn try_set_cooldowns<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    random_cooldown: Option<u64>,
    target_cooldown: Option<u64>,
    all_cooldown: Option<u64>,
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut save_it = false;
    // if setting random cooldown
    if let Some(rdm) = random_cooldown {
        if config.random_cool != rdm {
            config.random_cool = rdm;
            save_it = true;
        }
    }
    // if setting target cooldown
    if let Some(tgt) = target_cooldown {
        if config.target_cool != tgt {
            config.target_cool = tgt;
            save_it = true;
        }
    }
    // if setting all cooldown
    if let Some(all) = all_cooldown {
        if config.all_cool != all {
            config.all_cool = all;
            save_it = true;
        }
    }
    if save_it {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetCooldowns {
            random_cooldown: config.random_cool,
            target_cooldown: config.target_cool,
            all_cooldown: config.all_cool,
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
        QueryMsg::RevealStatus {} => query_status(&deps.storage),
        QueryMsg::Cooldowns {} => query_cooldowns(&deps.storage),
        QueryMsg::Admins { viewer, permit } => query_admins(deps, viewer, permit),
        QueryMsg::NftContract {} => query_nft_contract(deps),
    };
    pad_query_result(response, BLOCK_SIZE)
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

/// Returns QueryResult displaying the revelation status
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_status<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::RevealStatus {
        reveals_have_halted: config.halt,
    })
}

/// Returns QueryResult displaying the cooldowns
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_cooldowns<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::Cooldowns {
        random_cooldown: config.random_cool,
        target_cooldown: config.target_cool,
        all_cooldown: config.all_cool,
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

/// checks if a revealed variant has dependencies and reveals those if needed
///
/// # Arguments
///
/// * `category` - category index of the revealed variant
/// * `variant` - variant index of the revealed variant
/// * `depends` - list of traits that have multiple layers
/// * `current` - current image indices
/// * `natural` - complete image indices
fn reveal_dependencies(
    category: u8,
    variant: u8,
    depends: &[StoredDependencies],
    current: &mut Vec<u8>,
    natural: &[u8],
) {
    let id = StoredLayerId { category, variant };
    if let Some(dep) = depends.iter().find(|d| d.id == id) {
        for multi in dep.correlated.iter() {
            current[multi.category as usize] = natural[multi.category as usize];
        }
    }
}

/// Returns StdResult<Vec<String>>
///
/// reveals all traits
///
/// # Arguments
///
/// * `block_time` - block time
/// * `image` - a mutable reference to the token's ImageInfo
/// * `category_names` - the trait category names
/// * `skip` - the layers that do not get revealed individually
/// * `cooldown` - cooldown period for revealing all traits
/// * `revealed` - last time a reveal was done on this token, if applicable
fn all_reveal(
    block_time: u64,
    image: &mut ImageInfo,
    category_names: Vec<String>,
    skip: &[u8],
    cooldown: u64,
    revealed: Option<u64>,
) -> StdResult<Vec<String>> {
    let last = revealed.ok_or_else(|| StdError::generic_err("Your first reveal must be random"))?;
    // check cooldown period
    let charged = last + cooldown;
    if block_time < charged {
        return Err(StdError::generic_err(format!(
            "Can not reveal all traits until {}",
            charged
        )));
    }
    let unknowns = category_names
        .into_iter()
        .enumerate()
        .filter_map(|(i, n)| {
            if image.current[i] == 255 && !skip.contains(&(i as u8)) {
                Some(n)
            } else {
                None
            }
        })
        .collect::<Vec<String>>();
    if unknowns.is_empty() {
        return Err(StdError::generic_err(
            "All traits have already been revealed",
        ));
    }
    // reveal everything
    image.current = image.natural.clone();
    Ok(unknowns)
}

/// Returns StdResult<()>
///
/// reveals a targeted trait
///
/// # Arguments
///
/// * `block_time` - block time
/// * `image` - a mutable reference to the token's ImageInfo
/// * `svr_inf` - a reference to the ServeAlchemyResponse provided from the svg server
/// * `category` - name of the trait category to reveal
/// * `cooldown` - cooldown period for targeted reveals in seconds
/// * `revealed` - last time a reveal was done on this token, if applicable
fn target_reveal(
    block_time: u64,
    image: &mut ImageInfo,
    svr_inf: &ServeAlchemyResponse,
    category: &str,
    cooldown: u64,
    revealed: Option<u64>,
) -> StdResult<()> {
    let last = revealed.ok_or_else(|| StdError::generic_err("Your first reveal must be random"))?;
    // check cooldown period
    let charged = last + cooldown;
    if block_time < charged {
        return Err(StdError::generic_err(format!(
            "Can not reveal a targeted trait until {}",
            charged
        )));
    }
    // determine the targeted trait index
    let rvl_idx = svr_inf
        .category_names
        .iter()
        .position(|n| n == category)
        .ok_or_else(|| {
            StdError::generic_err(format!(
                "{} is not a valid trait category for this skull",
                category
            ))
        })?;
    if image.current[rvl_idx] != 255 {
        return Err(StdError::generic_err(
            "That trait has already been revealed",
        ));
    }
    // if there are any unknown traits left besides this one
    if image
        .current
        .iter()
        .enumerate()
        .any(|(i, u)| *u == 255 && i != rvl_idx && !svr_inf.skip.contains(&(i as u8)))
    {
        // reveal this one and all its dependencies
        image.current[rvl_idx] = image.natural[rvl_idx];
        reveal_dependencies(
            rvl_idx as u8,
            image.current[rvl_idx],
            &svr_inf.dependencies,
            &mut image.current,
            &image.natural,
        );
    } else {
        // this is the last so also remove any unknown markers on skipped layers
        image.current = image.natural.clone();
    }

    Ok(())
}

/// Returns StdResult<Vec<String>>
///
/// reveals a random trait and returns the trait category revealed
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `env` - Env of contract's environment
/// * `image` - a mutable reference to the token's ImageInfo
/// * `svr_inf` - ServeAlchemyResponse provided from the svg server
/// * `entropy` - entropy string slice used for rng
/// * `cooldown` - cooldown period for random reveals in seconds
/// * `revealed` - last time a reveal was done on this token, if applicable
fn random_reveal<S: ReadonlyStorage>(
    storage: &S,
    env: Env,
    image: &mut ImageInfo,
    mut svr_inf: ServeAlchemyResponse,
    entropy: &str,
    cooldown: u64,
    revealed: Option<u64>,
) -> StdResult<Vec<String>> {
    // if not the first reveal, check cooldown period
    if let Some(last) = revealed {
        let charged = last + cooldown;
        if env.block.time < charged {
            return Err(StdError::generic_err(format!(
                "Can not reveal a random trait until {}",
                charged
            )));
        }
    }
    // get list of indices of unknowns eligible for reveal
    let mut unknowns = image
        .current
        .iter()
        .enumerate()
        .filter_map(|(i, u)| {
            if *u == 255 && !svr_inf.skip.contains(&(i as u8)) {
                Some(i)
            } else {
                None
            }
        })
        .collect::<Vec<usize>>();
    let cnt = unknowns.len();
    if cnt == 0 {
        return Err(StdError::generic_err(
            "All traits have already been revealed",
        ));
    }
    // don't need to randomize if only one unknown left
    let cat_idx = if cnt == 1 {
        // also get rid of any unknown markers in unused skipped layers
        image.current = image.natural.clone();
        unknowns
            .pop()
            .ok_or_else(|| StdError::generic_err("Failed to pop an unknown trait"))?
    } else {
        // set up the rng
        let prng_seed: Vec<u8> = load(storage, PRNG_SEED_KEY)?;
        let rng_entropy = extend_entropy(
            env.block.height,
            env.block.time,
            &env.message.sender,
            entropy.as_bytes(),
        );
        let mut rng = Prng::new(&prng_seed, &rng_entropy);
        // select a random trait
        unknowns.shuffle(rng.get_rng());
        let rvl_idx = unknowns
            .pop()
            .ok_or_else(|| StdError::generic_err("Failed to pop an unknown trait"))?;
        // reveal it and any dependencies
        image.current[rvl_idx] = image.natural[rvl_idx];
        reveal_dependencies(
            rvl_idx as u8,
            image.current[rvl_idx],
            &svr_inf.dependencies,
            &mut image.current,
            &image.natural,
        );
        rvl_idx
    };

    Ok(vec![svr_inf.category_names.swap_remove(cat_idx)])
}
