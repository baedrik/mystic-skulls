use cosmwasm_std::{
    to_binary, Api, CanonicalAddr, Env, Extern, HandleResponse, HandleResult, HumanAddr,
    InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result},
};

use crate::msg::{
    HandleAnswer, HandleMsg, InitMsg, Keyphrase, QueryAnswer, QueryMsg, SolveResponse,
    StoredWinner, ViewerInfo, Winner,
};
use crate::rand::sha_256;
use crate::state::{
    Config, CONFIG_KEY, MY_ADDRESS_KEY, PREFIX_REVOKED_PERMITS, PREFIX_VIEW_KEY, PRNG_SEED_KEY,
};
use crate::storage::{load, may_load, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the puzzle contract
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
    let mut admins = vec![sender_raw];
    if let Some(addrs) = msg.admins {
        add_admins(&deps.api, &addrs, &mut admins)?;
    }
    let raw_kp: Vec<Keyphrase> = msg.keyphrases.unwrap_or_else(Vec::new);
    let config = Config {
        winners: raw_kp
            .into_iter()
            .map(|kp| StoredWinner {
                puzzle_info: sanitize_kp(kp),
                winner: None,
            })
            .collect(),
        admins,
    };
    save(&mut deps.storage, CONFIG_KEY, &config)?;

    Ok(InitResponse {
        messages: vec![],
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
        HandleMsg::AddKeyphrases { keyphrases } => {
            try_add_key_phrases(deps, &env.message.sender, keyphrases)
        }
        HandleMsg::RemoveKeyphrases { keyphrases } => {
            try_remove_key_phrases(deps, &env.message.sender, &keyphrases)
        }
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, &env.message.sender, key),
        HandleMsg::AddAdmins { admins } => try_add_admins(deps, &env.message.sender, &admins),
        HandleMsg::RemoveAdmins { admins } => try_remove_admins(deps, &env.message.sender, &admins),
        HandleMsg::Solve { solution } => try_solve(deps, &env.message.sender, solution),
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// checks if the sender is the first to solve a puzzle
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `solution` - the proposed solution Keyphrase
fn try_solve<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    solution: Keyphrase,
) -> HandleResult {
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let result = if let Some(wnr) = config
        .winners
        .iter_mut()
        .find(|w| w.puzzle_info.puzzle == solution.puzzle)
    {
        if wnr.winner.is_none() {
            if wnr.puzzle_info.keyphrase == sanitize_str(&solution.keyphrase) {
                let sender_raw = deps.api.canonical_address(sender)?;
                wnr.winner = Some(sender_raw);
                save(&mut deps.storage, CONFIG_KEY, &config)?;
                SolveResponse::Winner
            } else {
                SolveResponse::WrongAnswer
            }
        } else {
            SolveResponse::AlreadySolved
        }
    } else {
        return Err(StdError::generic_err(format!(
            "There is no puzzle with the name:  {}",
            solution.puzzle
        )));
    };
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Solve { result })?),
    })
}

/// Returns HandleResult
///
/// adds keyphrases
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `keyphrases` - list of keyphrases to add
fn try_add_key_phrases<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    keyphrases: Vec<Keyphrase>,
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let save_it = !keyphrases.is_empty();
    for kp in keyphrases.into_iter() {
        if config
            .winners
            .iter()
            .any(|w| w.puzzle_info.puzzle == kp.puzzle)
        {
            return Err(StdError::generic_err(format!(
                "There is already a puzzle with the name: {}",
                kp.puzzle
            )));
        }
        config.winners.push(StoredWinner {
            puzzle_info: sanitize_kp(kp),
            winner: None,
        });
    }
    // only save it if a keyphrase has been added
    if save_it {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::KeyphraseList {
            keyphrases: config.winners.into_iter().map(|w| w.puzzle_info).collect(),
        })?),
    })
}

/// Returns HandleResult
///
/// removes keyphrases
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `keyphrases` - list of keyphrases to remove
fn try_remove_key_phrases<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    keyphrases: &[String],
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let old_len = config.winners.len();
    config
        .winners
        .retain(|w| !keyphrases.contains(&w.puzzle_info.puzzle));
    // only save it if a keyphrase has been removed
    if old_len != config.winners.len() {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::KeyphraseList {
            keyphrases: config.winners.into_iter().map(|w| w.puzzle_info).collect(),
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
    // save list if it changed
    if add_admins(&deps.api, addrs_to_add, &mut config.admins)? {
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
        QueryMsg::Solved {} => query_solved(&deps.storage),
        QueryMsg::Admins { viewer, permit } => query_admins(deps, viewer, permit),
        QueryMsg::Winners { viewer, permit } => query_winners(deps, viewer, permit),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying all the puzzles' infos
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_winners<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (config, _) = check_admin(deps, viewer, permit)?;
    to_binary(&QueryAnswer::Winners {
        winners: config
            .winners
            .into_iter()
            .map(|w| w.into_human(&deps.api))
            .collect::<StdResult<Vec<Winner>>>()?,
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

/// Returns QueryResult displaying the puzzles that have been solved
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_solved<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::Solved {
        puzzles: config
            .winners
            .into_iter()
            .filter_map(|w| {
                if w.winner.is_some() {
                    Some(w.puzzle_info.puzzle)
                } else {
                    None
                }
            })
            .collect(),
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

/// Returns StdResult<bool> which is true if the admin list has changed after attempting
/// to add a list of addresses that do not collide
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addrs_to_add` - list of addresses to add
/// * `admins` - a mutable reference to the list of admins
fn add_admins<A: Api>(
    api: &A,
    addrs_to_add: &[HumanAddr],
    admins: &mut Vec<CanonicalAddr>,
) -> StdResult<bool> {
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = api.canonical_address(addr)?;
        if !admins.contains(&raw) {
            admins.push(raw);
            save_it = true;
        }
    }
    Ok(save_it)
}

/// Returns Keyphrase from removing whitespace and transforming to lowercase
///
/// # Arguments
///
/// * `input` - Keyphrase to sanitize
fn sanitize_kp(input: Keyphrase) -> Keyphrase {
    Keyphrase {
        puzzle: input.puzzle,
        keyphrase: sanitize_str(&input.keyphrase),
    }
}

/// Returns String from removing whitespace and transforming to lowercase
///
/// # Arguments
///
/// * `input` - string slice to sanitize
fn sanitize_str(input: &str) -> String {
    let mut buf = Vec::new();
    for c in input.chars() {
        if !c.is_whitespace() {
            for lc in c.to_lowercase() {
                buf.push(lc);
            }
        }
    }
    buf.into_iter().collect::<String>()
}
