use cosmwasm_std::{
    to_binary, Api, CanonicalAddr, Env, Extern, HandleResponse, HandleResult,
    HumanAddr, InitResponse, InitResult, Querier, QueryResult, StdError,
    StdResult, Storage, ReadonlyStorage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result},
};

use crate::msg::{
    HandleAnswer, HandleMsg, InitMsg, QueryAnswer, LayerId,
    QueryMsg, CategoryInfo, VariantInfo, VariantModInfo, Weights, ForcedVariants, ViewerInfo, VariantInfoPlus, Dependencies, StoredLayerId,
};
use crate::rand::{ extend_entropy, sha_256, Prng };
use crate::state::{
    Category, Variant, CommonMetadata, RollConfig, StoredDependencies, ADMINS_KEY, MY_ADDRESS_KEY, PREFIX_CATEGORY_MAP, PREFIX_VARIANT_MAP,
    PREFIX_CATEGORY, PREFIX_VARIANT, PREFIX_REVOKED_PERMITS,
    PREFIX_VIEW_KEY, PRNG_SEED_KEY, VIEWERS_KEY, MINTERS_KEY, NUM_CATS_KEY, METADATA_KEY, PREFIX_GENE, ROLL_CONF_KEY, DEPENDENCIES_KEY, HIDERS_KEY,
};
use crate::storage::{load, may_load, remove, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
use crate::metadata::{Metadata};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the server contract
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
    let admins = vec![sender_raw];
    save(&mut deps.storage, ADMINS_KEY, &admins)?;
    save(&mut deps.storage, NUM_CATS_KEY, &0u8)?;

    Ok(InitResponse::default())
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
        HandleMsg::SetRollConfig { skip, first } => try_set_roll_config(deps, &env.message.sender, skip, first),
        HandleMsg::AddCategories { categories } => {
            try_add_categories(deps, &env.message.sender, categories)
        }
        HandleMsg::AddVariants { variants } => try_add_variants(deps, &env.message.sender, variants),
        HandleMsg::ModifyCategory { name, new_name, forced_variants, weights } => try_modify_category(deps, &env.message.sender, &name, new_name, forced_variants, weights),
        HandleMsg::ModifyVariants { modifications } => try_modify_variants(deps, &env.message.sender, modifications),
        HandleMsg::SetMetadata { public_metadata, private_metadata } => try_set_metadata(deps, &env.message.sender, public_metadata, private_metadata),
        HandleMsg::AddGene { gene } => try_add_gene(deps, &env.message.sender, gene),
        HandleMsg::AddAdmins { admins } => {
            try_process_auth_list(deps, &env.message.sender, &admins, true, AddrType::Admin)
        }
        HandleMsg::RemoveAdmins { admins } => {
            try_process_auth_list(deps, &env.message.sender, &admins, false, AddrType::Admin)
        }
        HandleMsg::AddViewers { viewers } => {
            try_process_auth_list(deps, &env.message.sender, &viewers, true, AddrType::Viewer)
        }
        HandleMsg::RemoveViewers { viewers } => try_process_auth_list(
            deps,
            &env.message.sender,
            &viewers,
            false,
            AddrType::Viewer,
        ),
        HandleMsg::AddMinters { minters } => try_process_auth_list(
            deps,
            &env.message.sender,
            &minters,
            true,
            AddrType::Minter,
        ),
        HandleMsg::RemoveMinters { minters } => try_process_auth_list(
            deps,
            &env.message.sender,
            &minters,
            false,
            AddrType::Minter,
        ),
        HandleMsg::AddDependencies { dependencies } => try_process_dep_list(deps, &env.message.sender, &dependencies, Action::Add, true),
        HandleMsg::RemoveDependencies { dependencies } => try_process_dep_list(deps, &env.message.sender, &dependencies, Action::Remove, true),
        HandleMsg::ModifyDependencies { dependencies } => try_process_dep_list(deps, &env.message.sender, &dependencies, Action::Modify, true),
        HandleMsg::AddHiders { hiders } => try_process_dep_list(deps, &env.message.sender, &hiders, Action::Add, false),
        HandleMsg::RemoveHiders { hiders } => try_process_dep_list(deps, &env.message.sender, &hiders, Action::Remove, false),
        HandleMsg::ModifyHiders { hiders } => try_process_dep_list(deps, &env.message.sender, &hiders, Action::Modify, false),
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// adds a gene to avoid future duplication
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `gene` - image index array of recently minted NFT
fn try_add_gene<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    gene: Vec<u8>,
) -> HandleResult {
    // only allow minters to do this
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    let sender_raw = deps.api.canonical_address(sender)?;
    if !minters.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut gene_store = PrefixedStorage::new(PREFIX_GENE, &mut deps.storage);
    // can not allow a duplicate, even though this should have been weeded out before this msg
    if may_load::<bool, _>(&gene_store, &gene)?.is_some() {
        return Err(StdError::generic_err("This gene has already been minted"));
    }
    save(&mut gene_store, &gene, &true)?;
    Ok(HandleResponse::default())
}

/// Returns HandleResult
///
/// sets layer categories to skip when rolling and the ones to roll first
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `skip` - list of categories to skip when rolling
/// * `first` - list of categories that must be rolled first instead of in layer order
fn try_set_roll_config<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    skip: Vec<String>,
    first: Vec<String>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let numcats: u8 = load(&deps.storage, NUM_CATS_KEY)?;
    let mut roll: RollConfig = may_load(&deps.storage, ROLL_CONF_KEY)?.unwrap_or(RollConfig {
        cat_cnt: 0u8,
        skip: Vec::new(),
        first: Vec::new(),
    });
    // map string names to indices
    let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
    let skip_idx = skip.iter().map(|n| may_load::<u8, _>(&cat_map, n.as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Category name:  {} does not exist", n)))).collect::<StdResult<Vec<u8>>>()?;
    let first_idx = first.iter().map(|n| may_load::<u8, _>(&cat_map, n.as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Category name:  {} does not exist", n)))).collect::<StdResult<Vec<u8>>>()?;
    roll.cat_cnt = numcats;
    roll.skip = skip_idx;
    roll.first = first_idx;
    save(&mut deps.storage, ROLL_CONF_KEY, &roll)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetRollConfig { status: "success".to_string() })?),
    })
}

/// Returns HandleResult
///
/// sets the common metadata for all NFTs
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `public_metadata` - optional public metadata used for all NFTs
/// * `private_metadata` - optional private metadata used for all NFTs
fn try_set_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut common: CommonMetadata = may_load(&deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
        public: None,
        private: None,
    });

    let mut save_common = false;
    // update public metadata
    if let Some(pub_meta) = public_metadata {
        let new_pub = filter_metadata(pub_meta)?;
        if common.public != new_pub {
            common.public = new_pub;
            save_common = true;
        }
    }
    // update private metadata
    if let Some(priv_meta) = private_metadata {
        let new_priv = filter_metadata(priv_meta)?;
        if common.private != new_priv {
            common.private = new_priv;
            save_common = true;
        }
    }
    if save_common {
        // if both metadata are None, just remove it
        if common.public.is_none() && common.private.is_none() {
            remove(&mut deps.storage, METADATA_KEY);
        } else {
            save(&mut deps.storage, METADATA_KEY, &common)?;
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMetadata { status: "success".to_string() })?),
    })
}

/// Returns HandleResult
///
/// changes the name, forced variants, or weight tables of a trait category
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `name` - name of the category to change
/// * `new_name` - optional new name for the category
/// * `forced_variants` - optional new forced variants
/// * `weights` - optional new weight tables
fn try_modify_category<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    name: &str,
    new_name: Option<String>,
    forced_variants: Option<ForcedVariants>,
    weights: Option<Weights>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let cat_name_key = name.as_bytes();
    let mut cat_map = PrefixedStorage::new(PREFIX_CATEGORY_MAP, &mut deps.storage);
    if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
        let mut save_cat = false;
        let cat_key = cat_idx.to_le_bytes();
        let mut may_cat: Option<Category> = None;
        if let Some(new_nm) = new_name {
            if new_nm != name {
                // remove the mapping for the old name
                remove(&mut cat_map, cat_name_key);
                // map the category idx to the new name
                save(&mut cat_map, new_nm.as_bytes(), &cat_idx)?;
                let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
                let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err(format!("Category storage for {} is corrupt", name)))?;
                cat.name = new_nm;
                may_cat = Some(cat);
                save_cat = true;
            }
        }
        if let Some(forced) = forced_variants {
            let mut cat = may_cat.map_or_else(|| {
                let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
                may_load::<Category, _>(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err(format!("Category storage for {} is corrupt", name)))
            }, Ok)?;
            let var_map = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &cat_key], &deps.storage);
            let cyclops = forced.forced_cyclops.map(|f| {
                may_load::<u8, _>(&var_map, f.as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Category {} does not have a variant named {}", name, f)))
            }).transpose()?;
            if cat.forced_cyclops != cyclops {
                cat.forced_cyclops = cyclops;
                save_cat = true;
            }
            let jawless = forced.forced_jawless.map(|f| {
                may_load::<u8, _>(&var_map, f.as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Category {} does not have a variant named {}", name, f)))
            }).transpose()?;
            if cat.forced_jawless != jawless {
                cat.forced_jawless = jawless;
                save_cat = true;
            }
            may_cat = Some(cat);
        }
        if let Some(new_wgts) = weights {
            let mut cat = may_cat.map_or_else(|| {
                let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
                may_load::<Category, _>(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err(format!("Category storage for {} is corrupt", name)))
            }, Ok)?;
            let valid_len = cat.jawed_weights.len();
            if new_wgts.jawed_weights.len() != valid_len || new_wgts.jawless_weights.as_ref().filter(|w| w.len() != valid_len).is_some() {
                return Err(StdError::generic_err("New weight tables have incorrect length"));
            }
            if cat.jawed_weights != new_wgts.jawed_weights {
                cat.jawed_weights = new_wgts.jawed_weights;
                save_cat = true;
            }
            if cat.jawless_weights != new_wgts.jawless_weights {
                cat.jawless_weights = new_wgts.jawless_weights;
                save_cat = true;
            }
            may_cat = Some(cat);
        }
        if save_cat {
            let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
            save(&mut cat_store, &cat_key, &may_cat.ok_or_else(|| StdError::generic_err("May_cat can not be None if save_cat is true"))?)?;
        }
    } else {
        return Err(StdError::generic_err(format!("Category name:  {} does not exist", name)));
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ModifyCategory { status: "success".to_string() })?),
    })
}

/// Returns HandleResult
///
/// adds new trait categories
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `categories` - the new trait categories
fn try_add_categories<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    categories: Vec<CategoryInfo>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut numcats: u8 = load(&deps.storage, NUM_CATS_KEY)?;
    for cat_inf in categories.into_iter() {
        let cat_name_key = cat_inf.name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        if may_load::<u8, _>(&cat_map, cat_name_key)?.is_some() {
            return Err(StdError::generic_err(format!("Category name:  {} already exists", cat_inf.name)));
        }
        let mut jawed_weights: Vec<u16> = Vec::new();
        let mut jawless_weights: Option<Vec<u16>> = None;
        let cat_key = numcats.to_le_bytes();
        let (cyclops, jawless) = add_variants(&mut deps.storage, &cat_key, cat_inf.variants, &mut jawed_weights, &mut jawless_weights, cat_inf.forced_cyclops, cat_inf.forced_jawless, &cat_inf.name)?;
        // add the entry to the category map for this category name
        let mut cat_map = PrefixedStorage::new(PREFIX_CATEGORY_MAP, &mut deps.storage);
        save(&mut cat_map, cat_name_key, &numcats)?;
        let cat = Category {
            name: cat_inf.name,
            forced_cyclops: cyclops,
            forced_jawless: jawless,
            jawed_weights,
            jawless_weights,
        };
        let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
        save(&mut cat_store, &cat_key, &cat)?;
        numcats = numcats.checked_add(1).ok_or_else(|| StdError::generic_err("Reached maximum number of trait categories"))?;
    }
    save(&mut deps.storage, NUM_CATS_KEY, &numcats)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddCategories { count: numcats })?),
    })
}

/// Returns HandleResult
///
/// modifies existing trait variants
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `modifications` - the updated trait variants and the categories they belong to
fn try_modify_variants<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    modifications: Vec<VariantModInfo>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    for cat_inf in modifications.into_iter() {
        let cat_name = cat_inf.category;
        let cat_name_key = cat_name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        // if valid category name
        if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
            let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err(format!("Category storage for {} is corrupt", &cat_name)))?;
            let mut save_cat = false;
            for var_mod in cat_inf.modifications.into_iter() {
                let var_name_key = var_mod.name.as_bytes();
                let mut var_map = PrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &cat_key], &mut deps.storage);
                let var_idx: u8 = may_load(&var_map, var_name_key)?.ok_or_else(|| StdError::generic_err(format!("Category {} does not have a variant named {}", &cat_name, var_mod.name)))?;
                // if changing the variant name
                if var_mod.name != var_mod.modified_variant.name {
                    // remove the old name fomr the map and add the new one
                    remove(&mut var_map, var_name_key);
                    save(&mut var_map, var_mod.modified_variant.name.as_bytes(), &var_idx)?;
                }
                let var = Variant {
                    name: var_mod.modified_variant.name,
                    svg: var_mod.modified_variant.svg,
                };
                let this_wgt = cat.jawed_weights.get_mut(var_idx as usize).ok_or_else(|| StdError::generic_err(format!("Jawed weight table for category:  {} is corrupt", &cat_name)))?;
                // if weight is changing, update the table
                if *this_wgt != var_mod.modified_variant.jawed_weight {
                    *this_wgt = var_mod.modified_variant.jawed_weight;
                    save_cat = true;
                }
                // if providing a jawless weight
                if let Some(jawless) = var_mod.modified_variant.jawless_weight {
                    // can't add a jawless weight to a category that does not have them already
                    let this_jawless = cat.jawless_weights.as_mut().ok_or_else(|| StdError::generic_err(format!("Category:  {} does not have jawless weights, but variant {} does", &cat_name, &var.name)))?.get_mut(var_idx as usize).ok_or_else(|| StdError::generic_err(format!("Jawless weight table for category:  {} is corrupt", &cat_name)))?;
                    // if weight is changing, update the table
                    if *this_jawless != jawless {
                        *this_jawless = jawless;
                        save_cat = true;
                    }
                } else if cat.jawless_weights.is_some() {
                    // must provide a jawless weight for a category that has them
                    return Err(StdError::generic_err(format!("Category:  {} has jawless weights, but variant {} does not", &cat_name, &var.name)));
                }
                let mut var_store = PrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], &mut deps.storage);
                save(&mut var_store, &var_idx.to_le_bytes(), &var)?;
            }
            if save_cat {
                let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
                save(&mut cat_store, &cat_key, &cat)?;
            }
        } else {
            return Err(StdError::generic_err(format!("Category name:  {} does not exist", &cat_name)));
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ModifyVariants { status: "success".to_string() })?),
    })
}

/// Returns HandleResult
///
/// adds new trait variants to existing categories
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `variants` - the new trait variants and the categories they belong to
fn try_add_variants<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    variants: Vec<CategoryInfo>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    for cat_inf in variants.into_iter() {
        let cat_name_key = cat_inf.name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
            let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err(format!("Category storage for {} is corrupt", cat_inf.name)))?;
            add_variants(&mut deps.storage, &cat_key, cat_inf.variants, &mut cat.jawed_weights, &mut cat.jawless_weights, None, None, &cat_inf.name)?;
            let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
            save(&mut cat_store, &cat_key, &cat)?;
        } else {
            return Err(StdError::generic_err(format!("Category name:  {} does not exist", cat_inf.name)));
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddVariants { status: "success".to_string() })?),
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
        QueryMsg::AuthorizedAddresses { viewer, permit } => query_addresses(deps, viewer, permit),
        QueryMsg::Category { viewer, permit, name, index, start_at, limit, display_svg } => query_category(deps, viewer, permit, name.as_deref(), index, start_at, limit, display_svg),
        QueryMsg::Variant { viewer, permit, by_name, by_index, display_svg } => query_variant(deps, viewer, permit, by_name.as_ref(), by_index, display_svg),
        QueryMsg::CommonMetadata { viewer, permit } => query_common_metadata(deps, viewer, permit),
        QueryMsg::RollConfig { viewer, permit } => query_roll_config(deps, viewer, permit),
        QueryMsg::Dependencies { viewer, permit, start_at, limit } => query_dependencies(deps, viewer, permit, start_at, limit),
        QueryMsg::Hiders { viewer, permit, start_at, limit } => query_hiders(deps, viewer, permit, start_at, limit),
        QueryMsg::NewGene { viewer, height, time, sender, entropy, background } => query_new_gene(deps, viewer, height, time, &sender, &entropy, &background),
    };
    pad_query_result(response, BLOCK_SIZE)
}


/// Returns QueryResult which reveals the complete genetic image and current base reveal
/// image of a new, unique NFT
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
/// * `height` - the current block height
/// * `time` - the current block time
/// * `sender` - a reference to the address sending the mint tx
/// * `entropy` - entropy string slice for randomization
/// * `background` - background layer variant name
fn query_new_gene<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: ViewerInfo,
    height: u64,
    time: u64,
    sender: &HumanAddr,
    entropy: &str,
    background: &str,
) -> QueryResult {
    let (querier, _) = get_querier(deps, Some(viewer), None)?;
    // only allow minters to call this
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    if !minters.contains(&querier) {
        return Err(StdError::unauthorized());
    }
    let prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let rng_entropy = extend_entropy(height, time, sender, entropy.as_bytes());
    let mut rng = Prng::new(&prng_seed, &rng_entropy);
    let numcats: u8 = load(&deps.storage, NUM_CATS_KEY)?;
    let roll: RollConfig = may_load(&deps.storage, ROLL_CONF_KEY)?.unwrap_or(RollConfig {
        cat_cnt: numcats,
        skip: Vec::new(),
        first: Vec::new(),
    });
    let depends: Vec<StoredDependencies> = may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_else(Vec::new);
    let hiders: Vec<StoredDependencies> = may_load(&deps.storage, HIDERS_KEY)?.unwrap_or_else(Vec::new);
    let mut cat_cache: Vec<CatCache> = Vec::new();
    let mut none_cache: Vec<StoredLayerId> = Vec::new();

    // define some storages
    // background is always the first layer
    let background_map = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &0u8.to_le_bytes()], &deps.storage);
    let background_idx: u8 = may_load(&background_map, background.as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Background does not have a variant named {}", background)))?;
    let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
    let eye_type_idx: u8 = may_load(&cat_map, "Eye Type".as_bytes())?.ok_or_else(|| StdError::generic_err("Eye Type layer category not found"))?;
    let chin_idx: u8 = may_load(&cat_map, "Chin".as_bytes())?.ok_or_else(|| StdError::generic_err("Chin layer category not found"))?;
    
    let mut current_image: Vec<u8> = Vec::new();
    let mut genetic_image: Vec<u8> = Vec::new();
    let mut unique_check: Vec<u8> = Vec::new();
    let mut roll_it = true;
    while roll_it {
        let (reroll, current, genetic, unique) = new_gene_impl(&deps.storage, &mut rng, numcats, &roll, &depends, &hiders, eye_type_idx, chin_idx, background_idx, &mut none_cache, &mut cat_cache)?;
        if !reroll {
            current_image = current;
            genetic_image = genetic;
            unique_check = unique;
        }
        roll_it = reroll;
    }

    to_binary(&QueryAnswer::NewGene {
        current_image,
        genetic_image,
        unique_check,
    })
}

/// Returns QueryResult displaying the layer categories that should be skipped when rolling
/// and the ones that must be rolled first (and the total number of categories)
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_roll_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (_, _) = check_admin(deps, viewer, permit)?;
    let numcats: u8 = load(&deps.storage, NUM_CATS_KEY)?;
    let roll: RollConfig = may_load(&deps.storage, ROLL_CONF_KEY)?.unwrap_or(RollConfig {
        cat_cnt: numcats,
        skip: Vec::new(),
        first: Vec::new(),
    });
    // map indices to string names
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let skip = roll.skip.iter().map(|u| may_load::<Category, _>(&cat_store, &u.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Category storage is corrupt")).map(|r| r.name)).collect::<StdResult<Vec<String>>>()?;
    let first = roll.first.iter().map(|u| may_load::<Category, _>(&cat_store, &u.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Category storage is corrupt")).map(|r| r.name)).collect::<StdResult<Vec<String>>>()?;

    to_binary(&QueryAnswer::RollConfig {
        category_count: roll.cat_cnt,
        skip,
        first,
    })
}

/// Returns QueryResult displaying the trait variants that require other trait variants
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `start_at` - optional variant index to start the display
/// * `limit` - optional max number of variants to display
fn query_dependencies<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    start_at: Option<u16>,
    limit: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let max = limit.unwrap_or(100);
    let start = start_at.unwrap_or(0);
    let dependencies: Vec<StoredDependencies> = may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_else(Vec::new);
    let count = dependencies.len() as u16;
    to_binary(&QueryAnswer::Dependencies {
        count,
        dependencies: dependencies.iter().skip(start as usize).take(max as usize).map(|d| d.to_display(&deps.storage)).collect::<StdResult<Vec<Dependencies>>>()?,
    })
}

/// Returns QueryResult displaying the launch trait variants that hide other trait variants
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `start_at` - optional variant index to start the display
/// * `limit` - optional max number of variants to display
fn query_hiders<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    start_at: Option<u16>,
    limit: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let max = limit.unwrap_or(100);
    let start = start_at.unwrap_or(0);
    let dependencies: Vec<StoredDependencies> = may_load(&deps.storage, HIDERS_KEY)?.unwrap_or_else(Vec::new);
    let count = dependencies.len() as u16;
    to_binary(&QueryAnswer::Hiders {
        count,
        hiders: dependencies.iter().skip(start as usize).take(max as usize).map(|d| d.to_display(&deps.storage)).collect::<StdResult<Vec<Dependencies>>>()?,
    })
}

/// Returns QueryResult displaying a layer variant
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `by_name` - optional reference to the LayerId using string names
/// * `by_index` - optional StoredLayerId using indices
/// * `display_svg` - optionally true if svgs should be displayed
#[allow(clippy::too_many_arguments)]
fn query_variant<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    by_name: Option<&LayerId>,
    by_index: Option<StoredLayerId>,
    display_svg: Option<bool>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let svgs = display_svg.unwrap_or(false);
    let layer_id = if let Some(id) = by_index {
        id
    } else if let Some(id) = by_name {
        id.to_stored(&deps.storage)?
    } else {
        return Err(StdError::generic_err("Must specify a layer ID by either names or indices"));
    };
    // get the dependencies and hiders lists
    let depends: Vec<StoredDependencies> = may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_else(Vec::new);
    let hiders: Vec<StoredDependencies> = may_load(&deps.storage, HIDERS_KEY)?.unwrap_or_else(Vec::new);
    let cat_key = layer_id.category.to_le_bytes();
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
    let var_store = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], &deps. storage);
    // see if this variant requires other layer variants
    let includes = if let Some(dep) = depends.iter().find(|d| d.id == layer_id) {
        dep.correlated.iter().map(|l| l.to_display(&deps.storage)).collect::<StdResult<Vec<LayerId>>>()?
    } else {
        Vec::new()
    };
    // see if this variant hides other layer variants
    let hides_at_launch = if let Some(dep) = hiders.iter().find(|d| d.id == layer_id) {
        dep.correlated.iter().map(|l| l.to_display(&deps.storage)).collect::<StdResult<Vec<LayerId>>>()?
    } else {
        Vec::new()
    };
    let var: Variant = may_load(&var_store, &layer_id.variant.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
    let var_inf = VariantInfoPlus {
        index: layer_id.variant,
        variant_info: VariantInfo {
            name: var.name,
            svg: var.svg.filter(|_| svgs),
            jawed_weight: *cat.jawed_weights.get(layer_id.variant as usize).ok_or_else(|| StdError::generic_err("Jawed weight table is corrupt"))?,
            jawless_weight: cat.jawless_weights.map(|w| w.get(layer_id.variant as usize).cloned().ok_or_else(|| StdError::generic_err("Jawless weight table is corrupt"))).transpose()?,
        },
        includes,
        hides_at_launch,
    };
    to_binary(&QueryAnswer::Variant {
        category_index: layer_id.category,
        info: var_inf,
    })
}

/// Returns QueryResult displaying a trait category
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `name` - optional name of the category to display
/// * `index` - optional index of the category to display
/// * `start_at` - optional variant index to start the display
/// * `limit` - optional max number of variants to display
/// * `display_svg` - optionally true if svgs should be displayed
#[allow(clippy::too_many_arguments)]
fn query_category<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    name: Option<&str>,
    index: Option<u8>,
    start_at: Option<u8>,
    limit: Option<u8>,
    display_svg: Option<bool>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let svgs = display_svg.unwrap_or(false);
    let max = limit.unwrap_or_else(|| {
        if svgs {
            5
        } else {
            30
        }
    });
    let start = start_at.unwrap_or(0);
    let category_count: u8 = load(&deps.storage, NUM_CATS_KEY)?;
    let cat_idx = if let Some(nm) = name {
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        may_load::<u8, _>(&cat_map, nm.as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Category name:  {} does not exist", nm)))?
    } else if let Some(i) = index {
        if i >= category_count {
            return Err(StdError::generic_err(format!("There are only {} categories", category_count)));
        }
        i
    } else {
        0u8
    };
    let depends: Vec<StoredDependencies> = may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_else(Vec::new);
    let hiders: Vec<StoredDependencies> = may_load(&deps.storage, HIDERS_KEY)?.unwrap_or_else(Vec::new);
    let cat_key = cat_idx.to_le_bytes();
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
    let variant_count = cat.jawed_weights.len() as u8;
    let end = min(start + max, variant_count);
    let mut variants: Vec<VariantInfoPlus> = Vec::new();
    let var_store = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], &deps. storage);
    for idx in start..end {
        let layer_id = StoredLayerId {
            category: cat_idx,
            variant: idx,
        };
        // see if this variant requires other layer variants
        let includes = if let Some(dep) = depends.iter().find(|d| d.id == layer_id) {
            dep.correlated.iter().map(|l| l.to_display(&deps.storage)).collect::<StdResult<Vec<LayerId>>>()?
        } else {
            Vec::new()
        };
        // see if this variant hides other layer variants
        let hides_at_launch = if let Some(dep) = hiders.iter().find(|d| d.id == layer_id) {
            dep.correlated.iter().map(|l| l.to_display(&deps.storage)).collect::<StdResult<Vec<LayerId>>>()?
        } else {
            Vec::new()
        };
        let var: Variant = may_load(&var_store, &idx.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
        let var_inf = VariantInfoPlus {
            index: idx,
            variant_info: VariantInfo {
                name: var.name,
                svg: var.svg.filter(|_| svgs),
                jawed_weight: *cat.jawed_weights.get(idx as usize).ok_or_else(|| StdError::generic_err("Jawed weight table is corrupt"))?,
                jawless_weight: cat.jawless_weights.as_ref().map(|w| w.get(idx as usize).cloned().ok_or_else(|| StdError::generic_err("Jawless weight table is corrupt"))).transpose()?,
            },
            includes,
            hides_at_launch,
        };
        variants.push(var_inf);
    }
    let forced_cyclops = cat.forced_cyclops.map(|u| {
        may_load::<Variant, _>(&var_store, &u.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Variant storage is corrupt")).map(|v| v.name)
    }).transpose()?;
    let forced_jawless = cat.forced_jawless.map(|u| {
        may_load::<Variant, _>(&var_store, &u.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Variant storage is corrupt")).map(|v| v.name)
    }).transpose()?;
    to_binary(&QueryAnswer::Category {
        category_count,
        index: cat_idx,
        name: cat.name,
        forced_cyclops,
        forced_jawless,
        variant_count,
        variants,
    })
}

/// Returns QueryResult displaying the admin, minter, and viewer lists
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_addresses<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (admins, _) = check_admin(deps, viewer, permit)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_else(Vec::new);
    to_binary(&QueryAnswer::AuthorizedAddresses {
        admins: admins
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
        minters: minters
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
        viewers: viewers
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
    })
}

/// Returns QueryResult displaying the metadata common to all NFTs
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_common_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow authorized addresses to do this
    let (querier, _) = get_querier(deps, viewer, permit)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    if !minters.contains(&querier) {
        let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_else(Vec::new);
        if !viewers.contains(&querier) {
            let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
            if !admins.contains(&querier) {
                return Err(StdError::unauthorized());
            }
        }
    }
    let common: CommonMetadata = may_load(&deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
        public: None,
        private: None,
    });

    to_binary(&QueryAnswer::CommonMetadata {
        public_metadata: common.public,
        private_metadata: common.private,
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
            .ok_or_else(|| StdError::generic_err("Svg server contract address storage is corrupt"))?;
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

/// Returns StdResult<(Vec<CanonicalAddr>, Option<CanonicalAddr>)> which is the admin list
/// and this contract's address if it has been retrieved, and checks if the querier is an admin
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
) -> StdResult<(Vec<CanonicalAddr>, Option<CanonicalAddr>)> {
    let (admin, my_addr) = get_querier(deps, viewer, permit)?;
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    if !admins.contains(&admin) {
        return Err(StdError::unauthorized());
    }
    Ok((admins, my_addr))
}

pub enum AddrType {
    Admin,
    Viewer,
    Minter,
}

/// Returns HandleResult
///
/// updates the admin, viewer, or minter authorization list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of addresses to use for update
/// * `is_add` - true if the update is for adding to the list
/// * `list` - AddrType to determine which list to update
fn try_process_auth_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    update_list: &[HumanAddr],
    is_add: bool,
    list: AddrType,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    // get the right authorization list info
    let (mut current_list, key) = match list {
        AddrType::Admin => (admins, ADMINS_KEY),
        AddrType::Viewer => (
            may_load::<Vec<CanonicalAddr>, _>(&deps.storage, VIEWERS_KEY)?.unwrap_or_else(Vec::new),
            VIEWERS_KEY,
        ),
        AddrType::Minter => (
            may_load::<Vec<CanonicalAddr>, _>(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new),
            MINTERS_KEY,
        ),
    };
    // update the authorization list if needed
    let save_it = if is_add {
        add_addrs_to_auth(&deps.api, &mut current_list, update_list)?
    } else {
        remove_addrs_from_auth(&deps.api, &mut current_list, update_list)?
    };
    // save list if it changed
    if save_it {
        save(&mut deps.storage, key, &current_list)?;
    }
    let new_list = current_list
        .iter()
        .map(|a| deps.api.human_address(a))
        .collect::<StdResult<Vec<HumanAddr>>>()?;
    let resp = match list {
        AddrType::Admin => HandleAnswer::AdminsList { admins: new_list },
        AddrType::Viewer => HandleAnswer::ViewersList {
            viewers: new_list,
        },
        AddrType::Minter => HandleAnswer::MintersList { minters: new_list },
    };
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&resp)?),
    })
}

/// Returns StdResult<bool>
///
/// adds to an authorization list of addresses and returns true if the list changed
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addresses` - current mutable list of addresses
/// * `addrs_to_add` - list of addresses to add
fn add_addrs_to_auth<A: Api>(
    api: &A,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_add: &[HumanAddr],
) -> StdResult<bool> {
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = api.canonical_address(addr)?;
        if !addresses.contains(&raw) {
            addresses.push(raw);
            save_it = true;
        }
    }
    Ok(save_it)
}

/// Returns StdResult<bool>
///
/// removes from an authorization list of addresses and returns true if the list changed
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addresses` - current mutable list of addresses
/// * `addrs_to_remove` - list of addresses to remove
fn remove_addrs_from_auth<A: Api>(
    api: &A,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_remove: &[HumanAddr],
) -> StdResult<bool> {
    let old_len = addresses.len();
    let rem_list = addrs_to_remove
        .iter()
        .map(|a| api.canonical_address(a))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    addresses.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    Ok(old_len != addresses.len())
}

/// Returns StdResult<(Option<u8>, Option<u8>)>
///
/// adds new trait variants to the specified category index and returns forced_cyclops and
/// forced_jawless mapped to their indices
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `cat_key` - index of the category these variants belong to
/// * `variants` - variants to add to this category
/// * `jawed_weights` - the jawed weight table for this category
/// * `jawless_weights` - the optional jawless weight table for this category
/// * `forced_cyclops` - optional variant name that cyclops have to use
/// * `forced_jawless` - optional variant name that jawless have to use
/// * `cat_name` - name of this trait category
#[allow(clippy::too_many_arguments)]
fn add_variants<S: Storage>(
    storage: &mut S,
    cat_key: &[u8],
    variants: Vec<VariantInfo>,
    jawed_weights: &mut Vec<u16>,
    jawless_weights: &mut Option<Vec<u16>>,
    mut forced_cyclops: Option<String>,
    mut forced_jawless: Option<String>,
    cat_name: &str,
) -> StdResult<(Option<u8>, Option<u8>)> {
    let mut var_cnt = jawed_weights.len() as u8;
    let mut cyclops_idx: Option<u8> = None;
    let mut jawless_idx: Option<u8> = None;
    for var_inf in variants.into_iter() {
        if let Some(cycl) = forced_cyclops.as_deref() {
            if cycl == var_inf.name {
                cyclops_idx = Some(var_cnt);
                forced_cyclops = None;
            }
        }
        if let Some(jwl) = forced_jawless.as_deref() {
            if jwl == var_inf.name {
                jawless_idx = Some(var_cnt);
                forced_jawless = None;
            }
        }
        let var = Variant {
            name: var_inf.name,
            svg: var_inf.svg,
        };
        let var_name_key = var.name.as_bytes();
        let mut var_map = PrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, cat_key], storage);
        if may_load::<u8, _>(&var_map, var_name_key)?.is_some() {
            return Err(StdError::generic_err(format!("Variant name:  {} already exists under category:  {}", &var.name, &cat_name)));
        }
        jawed_weights.push(var_inf.jawed_weight);
        // if this is the first variant
        if var_cnt == 0 {
            if let Some(jawless) = var_inf.jawless_weight {
                let _ = jawless_weights.insert(vec![jawless]);
            }
        // already have variants
        } else if let Some(jawless) = var_inf.jawless_weight {
            // can't add a jawless weight to a category that does not have them already
            jawless_weights.as_mut().ok_or_else(|| StdError::generic_err(format!("Category:  {} does not have jawless weights, but variant {} does", &cat_name, &var.name)))?.push(jawless);
        } else if jawless_weights.is_some() {
            // must provide a jawless weight for a category that has them
            return Err(StdError::generic_err(format!("Category:  {} has jawless weights, but variant {} does not", &cat_name, &var.name)));
        }
        save(&mut var_map, var_name_key, &var_cnt)?;
        let mut var_store = PrefixedStorage::multilevel(&[PREFIX_VARIANT, cat_key], storage);
        save(&mut var_store, &var_cnt.to_le_bytes(), &var)?;
        var_cnt = var_cnt.checked_add(1).ok_or_else(|| StdError::generic_err(format!("Reached maximum number of variants for category: {}", &cat_name)))?;
    }
    // if never found the forced cyclops variant
    if let Some(cycl) = forced_cyclops {
        return Err(StdError::generic_err(format!("Forced cyclops variant {} does not exist", cycl)));
    }
    // if never found the forced jawless variant
    if let Some(jwl) = forced_jawless {
        return Err(StdError::generic_err(format!("Forced jawless variant {} does not exist", jwl)));
    }
    Ok((cyclops_idx, jawless_idx))
}

/// Returns StdResult<Option<Metadata>>
///
/// filter metadata to error if both token_uri and extension are present, or to be
/// None if neither are present
///
/// # Arguments
///
/// * `metadata` - Metadata being screened
fn filter_metadata(metadata: Metadata) -> StdResult<Option<Metadata>> {
    let has_uri = metadata.token_uri.is_some();
    let has_xten = metadata.extension.is_some();
    // if you have both or have neither
    let new_meta = if has_uri == has_xten {
        // if both
        if has_uri {
            return Err(StdError::generic_err(
                "Metadata can not have BOTH token_uri AND extension",
            ));
        }
        // delete the existing if all fields are None
        None
    } else {
        Some(metadata)
    };
    Ok(new_meta)
}

/// Returns StdResult<()>
///
/// adds new dependencies to the specified list
///
/// # Arguments
///
/// * `storage` - a mutable reference to contract storage
/// * `dependencies` - list of new dependencies
/// * `key` - key for the dependency list to update
fn add_dependencies<S: Storage>(
    storage: &mut S,
    dependencies: &[Dependencies],
    key: &[u8],
) -> StdResult<()> {
    let mut depends: Vec<StoredDependencies> = may_load(storage, key)?.unwrap_or_else(Vec::new);
    for dep in dependencies.iter() {
        let stored = dep.to_stored(storage)?;
        // add if this variant does not already have dependencies
        if !depends.iter().any(|d| d.id == stored.id) {
            depends.push(stored);
        }
    }
    save(storage, key, &depends)
}

/// Returns HandleResult
///
/// removes dependencies from the specified list
///
/// # Arguments
///
/// * `storage` - a mutable reference to contract storage
/// * `dependencies` - list of dependencies to remove
/// * `key` - key for the dependency list to update
fn remove_dependencies<S: Storage>(
    storage: &mut S,
    dependencies: &[Dependencies],
    key: &[u8],
) -> StdResult<()> {
    if let Some(mut depends) = may_load::<Vec<StoredDependencies>, _>(storage, key)? {
        let old_len = depends.len();
        let rem_list = dependencies
            .iter()
            .map(|d| d.to_stored(storage))
            .collect::<StdResult<Vec<StoredDependencies>>>()?;
        depends.retain(|d| !rem_list.iter().any(|r| r.id == d.id));
        // only save if the list changed
        if old_len != depends.len() {
            save(storage, key, &depends)?;
        }
    }
    Ok(())
}

/// Returns HandleResult
///
/// modifies existing dependencies in the specified list
///
/// # Arguments
///
/// * `storage` - a mutable reference to contract storage
/// * `dependencies` - list of dependencies to modify
/// * `key` - key for the dependency list to update
fn modify_dependencies<S: Storage>(
    storage: &mut S,
    dependencies: &[Dependencies],
    key: &[u8],
) -> StdResult<()> {
    let mut depends: Vec<StoredDependencies> = may_load(storage, key)?.unwrap_or_else(Vec::new);
    let mut save_dep = false;
    for dep in dependencies.iter() {
        let stored = dep.to_stored(storage)?;
        let existing = depends.iter_mut().find(|d| d.id == stored.id);
        if let Some(update) = existing {
            *update = stored;
            save_dep = true;
        } else {
            return Err(StdError::generic_err(format!("No existing dependencies for Variant: {} in Category: {}", dep.id.variant, dep.id.category)));
        }
    }
    if save_dep {
        save(storage, key, &depends)?;
    }
    Ok(())
}

pub enum Action {
    Add,
    Remove,
    Modify,
}

/// Returns HandleResult
///
/// updates the required and hiding dependencies lists
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of dependencies to use for update
/// * `action` - Action to perform on the dependency list
/// * `is_required` - true if the dependencies list being updated is the one for requirements
fn try_process_dep_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    update_list: &[Dependencies],
    action: Action,
    is_required: bool,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let key = if is_required {
        DEPENDENCIES_KEY
    } else {
        HIDERS_KEY
    };
    let status = "success".to_string();
    let resp = match action {
        Action::Add => { 
            add_dependencies(&mut deps.storage, update_list, key)?;
            if is_required {
                HandleAnswer::AddDependencies { status }
            } else {
                HandleAnswer::AddHiders { status }
            }
        },
        Action::Remove => {
            remove_dependencies(&mut deps.storage, update_list, key)?;
            if is_required {
                HandleAnswer::RemoveDependencies { status }
            } else {
                HandleAnswer::RemoveHiders { status }
            }
        },
        Action::Modify => {
            modify_dependencies(&mut deps.storage, update_list, key)?;
            if is_required {
                HandleAnswer::ModifyDependencies { status }
            } else {
                HandleAnswer::ModifyHiders { status }
            }
        },
    };
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&resp)?),
    })
}

/// Returns HandleResult
///
/// picks a random winner out of a weight table
///
/// # Arguments
///
/// * `prng` - a mutable reference to the prng
/// * `weights` - weight table
fn draw_variant(
    prng: &mut Prng,
    weights: &[u16],
) -> u8 {
    let total_weight: u16 = weights.iter().sum();
    let rdm = u64::from_be_bytes(prng.eight_bytes());
    let winning_num: u16 = (rdm % total_weight as u64) as u16;
    let mut tally = 0u16;
    let mut winner = 0u8;
    for (idx, weight) in weights.iter().enumerate() {
        // if the sum didn't panic on overflow, it can't happen here
        tally += weight;
        if tally > winning_num {
            winner = idx as u8;
            break;
        }
    }
    winner
}

/// Returns StdResult<Option<Vec<u8>>>
///
/// checks if a complete genetic image is unique after ignoring any traits that are hidden by
/// other traits
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `genetic` - reference to the genetic image
/// * `hiders` - list of variants that hide other variants
/// * `numcats` - total number of categories
/// * `none_cache` - list of None trait variants that have already been retrieved
fn check_unique<S: ReadonlyStorage>(
    storage: &S,
    genetic: &[u8],
    hiders: &[StoredDependencies],
    numcats: u8,
    none_cache: &mut Vec<StoredLayerId>,
) -> StdResult<Option<Vec<u8>>> {
    let mut temp: Vec<u8> = genetic.to_owned();
    for idx in 1u8..numcats {
        let this_var = StoredLayerId {
            category: idx,
            variant: genetic[idx as usize],
        };
        if let Some(hider) = hiders.iter().find(|h| h.id == this_var) {
            for hidden in hider.correlated.iter() {
                if genetic[hidden.category as usize] == hidden.variant {
                    let none_idx = if let Some(var) = none_cache.iter().find(|n| n.category == hidden.category) {
                        var.variant
                    } else {
                        let var_map = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &hidden.category.to_le_bytes()], storage);
                        let idx: u8 = may_load(&var_map, "None".as_bytes())?.ok_or_else(|| StdError::generic_err("A hidden variant's category does not have a None variant"))?;
                        none_cache.push(StoredLayerId {
                            category: hidden.category,
                            variant: idx,
                        });
                        idx
                    };
                    temp[hidden.category as usize] = none_idx;
                }
            }
        }
    }
    // don't consider background
    let unique = temp.split_off(1);
    let gene_store = ReadonlyPrefixedStorage::new(PREFIX_GENE, storage);
    let resp = if may_load::<bool, _>(&gene_store, &unique)?.is_some() {
        None
    } else {
        Some(unique)
    };
    Ok(resp)
}

/// used to cache categories
pub struct CatCache {
    pub index: u8,
    pub category: Category,
}

/// Returns StdResult<(bool, Vec<u8>, Vec<u8>, Vec<u8>)>
///
/// creates a random NFT, and returns the revealed image, complete genetic image, and 
/// uniqueness mask if it was able to find a unique image without having to reroll the
/// archetype.  If it couldn't, it returns true to signify the need to start over
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `rng` - a mutable reference to the Prng
/// * `numcats` - total number of categories
/// * `roll` - a reference to the RollConfig
/// * `depends` - list of traits that have multiple layers
/// * `hiders` - list of variants that hide other variants
/// * `eye_type_idx` - Eye Type category index
/// * `chin_idx` - Chin category index
/// * `background_idx` - background variant index
/// * `none_cache` - list of None trait variants that have already been retrieved
/// * `cat_cache` - list of Categories that have already been retrieved
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn new_gene_impl<S: ReadonlyStorage>(
    storage: &S,
    rng: &mut Prng,
    numcats: u8,
    roll: &RollConfig,
    depends: &[StoredDependencies],
    hiders: &[StoredDependencies],
    eye_type_idx: u8,
    chin_idx: u8,
    background_idx: u8,
    none_cache: &mut Vec<StoredLayerId>,
    cat_cache: &mut Vec<CatCache>,
) -> StdResult<(bool, Vec<u8>, Vec<u8>, Vec<u8>)> {
    // define some storages
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, storage);
    let eye_type_var_store = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &eye_type_idx.to_le_bytes()], storage);
    let chin_var_store = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &chin_idx.to_le_bytes()], storage);

    let mut current_image: Vec<u8> = vec![255; numcats as usize];
    let mut genetic_image: Vec<u8> = current_image.clone();
    let mut skipping: Vec<bool> = vec![false; numcats as usize];
    // never have to roll the background
    skipping[0] = true;
    // any layers being skipped should be set to None
    for skip_cat in roll.skip.iter() {
        let none_idx = if let Some(var) = none_cache.iter().find(|n| n.category == *skip_cat) {
            var.variant
        } else {
            let var_map = ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &skip_cat.to_le_bytes()], storage);
            let idx: u8 = may_load(&var_map, "None".as_bytes())?.ok_or_else(|| StdError::generic_err(format!("Skipped category {} does not have a None variant", skip_cat)))?;
            // add to the none cache
            none_cache.push(StoredLayerId {
                category: *skip_cat,
                variant: idx,
            });
            idx
        };
        genetic_image[*skip_cat as usize] = none_idx;
        skipping[*skip_cat as usize] = true;
    }
    // set the background
    current_image[0] = background_idx;
    genetic_image[0] = background_idx;
    let mut is_cyclops = false;
    let mut is_jawless = false;

    // roll the ones that should be first
    for inits in roll.first.iter() {
        let cat = if let Some(c) = cat_cache.iter().find(|c| c.index == *inits) {
            &c.category
        } else {
            let c: Category = may_load(&cat_store, &inits.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
            cat_cache.push(CatCache {
                index: *inits,
                category: c,
            });
            &cat_cache.last().ok_or_else(|| StdError::generic_err("We just pushed a CatCache!"))?.category
        };
        let winner = draw_variant(rng, &cat.jawed_weights);
        // if we picked an eye type
        if *inits == eye_type_idx {
            let eye_type: Variant = may_load(&eye_type_var_store, &winner.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Eye Type variant storage is corrupt"))?;
            is_cyclops = eye_type.name == *"Cyclops";
        } else if *inits == chin_idx {
            let chin: Variant = may_load(&chin_var_store, &winner.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Chin variant storage is corrupt"))?;
            is_jawless = chin.name == *"None";
        }
        // archetype traits are revealed immediately
        current_image[*inits as usize] = winner;
        genetic_image[*inits as usize] = winner;
        skipping[*inits as usize] = true;
    }

    let mut idx = 1u8;
    let mut first_pass = true;
    // roll the rest
    loop {
        // if already rolled every trait
        if idx >= numcats  {
            if let Some(unique_check) = check_unique(storage, &genetic_image, hiders, numcats, none_cache)? {
                return Ok((false, current_image, genetic_image, unique_check));
            }
            // if skipping everything, return to try rerolling everything
            if skipping.iter().all(|b| *b) {
                return Ok((true, Vec::new(), Vec::new(), Vec::new()));
            }
            // start rerolling
            first_pass = false;
            idx = 1u8;
            continue;
        }
        if !*skipping.get(idx as usize).ok_or_else(|| StdError::generic_err("Skipping index out of bounds"))? {
            let cat = if let Some(c) = cat_cache.iter().find(|c| c.index == idx) {
                &c.category
            } else {
                let c: Category = may_load(&cat_store, &idx.to_le_bytes())?.ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
                cat_cache.push(CatCache {
                    index: idx,
                    category: c,
                });
                &cat_cache.last().ok_or_else(|| StdError::generic_err("We just pushed a CatCache!"))?.category
            };
            // grab the right weight table
            let weights = if is_jawless {
                cat.jawless_weights.as_ref().map_or(&cat.jawed_weights, |w| w)
            } else {
                &cat.jawed_weights
            };
            // see if there is a forced variant
            let forced = if is_cyclops {
                cat.forced_cyclops.as_ref()
            } else if is_jawless {
                cat.forced_jawless.as_ref()
            } else {
                None
            };
            // forced variants are revealed immediately
            let winner = if let Some(f) = forced {
                current_image[idx as usize] = *f;
                // don't attempt to reroll a forced variant
                skipping[idx as usize] = true;
                *f
            } else {
                draw_variant(rng, weights)
            };
            genetic_image[idx as usize] = winner;
            // add additional layers for this trait if necessary
            let id = StoredLayerId {
                category: idx,
                variant: winner,
            };
            if let Some(dep) = depends.iter().find(|d| d.id == id) {
                for multi in dep.correlated.iter() {
                    genetic_image[multi.category as usize] = multi.variant;
                    // don't reroll a dependency
                    skipping[multi.category as usize] = true;
                }
                // don't break dependencies by rerolling a trait that had dependencies
                skipping[idx as usize] = true;
            }
            // if already rolled every trait, see if you have a unique gene
            if !first_pass {
                if let Some(unique_check) = check_unique(storage, &genetic_image, hiders, numcats, none_cache)? {
                    return Ok((false, current_image, genetic_image, unique_check));
                }
            }
        }
        idx +=1;
    }
}
