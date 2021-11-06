use cosmwasm_std::{
    log, to_binary, Api, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse, HandleResult,
    HumanAddr, InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError,
    StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
};

use crate::contract_info::{ContractInfo, StoreContractInfo};
use crate::factory_msgs::FactoryHandleMsg;
use crate::msg::{
    HandleAnswer, HandleMsg, InitMsg, QueryAnswer,
    QueryMsg, CategoryInfo, VariantInfo, VariantModInfo, Weights, ForcedVariants, ViewerInfo,
};
use crate::rand::sha_256;
use crate::state::{
    Category, Variant, CommonMetadata, ADMINS_KEY, MY_ADDRESS_KEY, PREFIX_CATEGORY_MAP, PREFIX_VARIANT_MAP,
    PREFIX_CATEGORY, PREFIX_VARIANT, PREFIX_REVOKED_PERMITS,
    PREFIX_VIEW_KEY, PRNG_SEED_KEY, VIEWERS_KEY, MINTERS_KEY, NUM_CATS_KEY, METADATA_KEY, PREFIX_GENE,
};
use crate::storage::{load, may_load, remove, save};
use crate::template::{MintAuthCache, StoredTemplate, Template, TemplateInfo};
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
    let gene_store = PrefixedStorage::new(PREFIX_GENE, &mut deps.storage);
    // can not allow a duplicate, even though this should have been weeded out before this msg
    if may_load::<bool, _>(&gene_store, &gene)?.is_some() {
        return Err(StdError::generic_err("This gene has already been minted"));
    }
    save(&mut gene_store, &gene, &true)?;
    Ok(HandleResponse::default())
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
        // delete the existing is all fields are None
        let new_pub = if pub_meta.token_uri.is_none() && pub_meta.extension.is_none() {
            None
        } else {
            Some(pub_meta)
        };
        if common.public != new_pub {
            common.public = new_pub;
            save_common = true;
        }
    }
    // update private metadata
    if let Some(priv_meta) = private_metadata {
        // delete the existing is all fields are None
        let new_priv = if priv_meta.token_uri.is_none() && priv_meta.extension.is_none() {
            None
        } else {
            Some(priv_meta)
        };
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
                may_cat.insert(cat);
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
            may_cat.insert(cat);
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
            may_cat.insert(cat);
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
        let cat_name_key = cat_inf.category.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        // if valid category name
        if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
            let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| StdError::generic_err(format!("Category storage for {} is corrupt", cat_inf.category)))?;
            let mut save_cat = false;
            for var_mod in cat_inf.modifications.into_iter() {
                let var_name_key = var_mod.name.as_bytes();
                let mut var_map = PrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &cat_key], &mut deps.storage);
                let var_idx: u8 = may_load(&var_map, var_name_key)?.ok_or_else(|| StdError::generic_err(format!("Category {} does not have a variant named {}", cat_inf.category, var_mod.name)))?;
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
                let this_wgt = cat.jawed_weights.get_mut(var_idx as usize).ok_or_else(|| StdError::generic_err(format!("Jawed weight table for category:  {} is corrupt", cat_inf.category)))?;
                // if weight is changing, update the table
                if *this_wgt != var_mod.modified_variant.jawed_weight {
                    *this_wgt = var_mod.modified_variant.jawed_weight;
                    save_cat = true;
                }
                // if providing a jawless weight
                if let Some(jawless) = var_mod.modified_variant.jawless_weight {
                    // can't add a jawless weight to a category that does not have them already
                    let this_jawless = cat.jawless_weights.as_mut().ok_or_else(|| StdError::generic_err(format!("Category:  {} does not have jawless weights, but variant {} does", cat_inf.category, var_mod.modified_variant.name)))?.get_mut(var_idx as usize).ok_or_else(|| StdError::generic_err(format!("Jawless weight table for category:  {} is corrupt", cat_inf.category)))?;
                    // if weight is changing, update the table
                    if *this_jawless != jawless {
                        *this_jawless = jawless;
                        save_cat = true;
                    }
                } else if cat.jawless_weights.is_some() {
                    // must provide a jawless weight for a category that has them
                    return Err(StdError::generic_err(format!("Category:  {} has jawless weights, but variant {} does not", cat_inf.category, var_mod.modified_variant.name)));
                }
                let mut var_store = PrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], &mut deps.storage);
                save(&mut var_store, &var_idx.to_le_bytes(), &var)?;
            }
            if save_cat {
                let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
                save(&mut cat_store, &cat_key, &cat)?;
            }
        } else {
            return Err(StdError::generic_err(format!("Category name:  {} does not exist", cat_inf.category)));
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
        QueryMsg::Template {
            viewer,
            permit,
            template_name,
        } => query_template(deps, viewer, permit, &template_name),
        QueryMsg::AllTemplates {
            viewer,
            permit,
            page,
            page_size,
        } => query_templates(deps, viewer, permit, page, page_size),
        QueryMsg::AllNftContracts {
            viewer,
            permit,
            page,
            page_size,
        } => query_contracts(deps, viewer, permit, page, page_size),
        QueryMsg::PublicDescriptionOfNfts {
            template_names,
            page,
            page_size,
        } => query_pub_desc(deps, template_names, page, page_size),
        QueryMsg::NftListingDisplay { option_id } => query_listing_disp(deps, option_id),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying information about all nft contracts this minter uses
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of contracts to display
fn query_contracts<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let start = page * limit;
    let state: State = load(&deps.storage, STATE_KEY)?;
    let end = min(start + limit, state.contract_cnt);
    let mut nft_contracts: Vec<ContractInfo> = Vec::new();
    let contr_store = ReadonlyPrefixedStorage::new(PREFIX_CONTRACT, &deps.storage);
    for idx in start..end {
        let may_contr: Option<StoreContractInfo> = may_load(&contr_store, &idx.to_le_bytes())?;
        if let Some(c) = may_contr {
            nft_contracts.push(c.into_humanized(&deps.api)?);
        }
    }

    to_binary(&QueryAnswer::AllNftContracts {
        contract_count: state.contract_cnt,
        nft_contracts,
    })
}

/// Returns QueryResult displaying information about all templates
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of templates to display
fn query_templates<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    let (_, may_addr) = check_admin(deps, viewer, permit)?;
    let my_addr_raw = may_addr.map_or_else(
        || {
            may_load::<CanonicalAddr, _>(&deps.storage, MY_ADDRESS_KEY)?
                .ok_or_else(|| StdError::generic_err("Minter contract address storage is corrupt"))
        },
        Ok,
    )?;
    let my_addr = deps.api.human_address(&my_addr_raw)?;
    let viewing_key: String = may_load(&deps.storage, MY_VIEWING_KEY)?
        .ok_or_else(|| StdError::generic_err("Minter contract's viewing key storage is corrupt"))?;
    let viewer = ViewerInfo {
        address: my_addr,
        viewing_key,
    };
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let start = page * limit;
    let state: State = load(&deps.storage, STATE_KEY)?;
    let end = min(start + limit, state.template_cnt);
    let mut templates: Vec<TemplateInfo> = Vec::new();
    let mut cache: Vec<MintAuthCache> = Vec::new();
    let templ_store = ReadonlyPrefixedStorage::new(PREFIX_TEMPLATE, &deps.storage);
    for idx in start..end {
        let may_templ: Option<StoredTemplate> = may_load(&templ_store, &idx.to_le_bytes())?;
        if let Some(t) = may_templ {
            templates.push(t.into_humanized(deps, &mut cache, viewer.clone())?);
        }
    }

    to_binary(&QueryAnswer::AllTemplates {
        template_count: state.template_cnt,
        templates,
    })
}

/// Returns QueryResult displaying public information about the next nfts the specified
/// templates will mint
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `template_names` - optional list of template names to view
/// * `page` - optional page to display
/// * `page_size` - optional number of templates to display
fn query_pub_desc<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    template_names: Option<Vec<String>>,
    page: Option<u16>,
    page_size: Option<u16>,
) -> QueryResult {
    let idxs = get_idxs(&deps.storage, template_names)?;
    let count = idxs.len() as u16;
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let skip = page * limit;
    let paged = idxs
        .into_iter()
        .skip(skip as usize)
        .take(limit as usize)
        .collect::<Vec<u16>>();
    let nft_infos = get_pub_desc(deps, &paged)?;
    to_binary(&QueryAnswer::PublicDescriptionOfNfts { count, nft_infos })
}

/// Returns QueryResult displaying public information about the next nft the specified
/// template will mint
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `option_id` - template name to view
fn query_listing_disp<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    option_id: String,
) -> QueryResult {
    let idx = get_idxs(&deps.storage, Some(vec![option_id]))?;
    let pub_desc = get_pub_desc(deps, &idx)?
        .pop()
        .ok_or_else(|| StdError::generic_err("Failed to retrieve the NFT listing info"))?;
    to_binary(&QueryAnswer::NftListingDisplay {
        nft_info: pub_desc.nft_info,
        nft_contract_address: pub_desc.nft_contract_address,
        mintable: pub_desc.mintable,
    })
}

/// Returns QueryResult displaying information about a single template
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `template_name` - String slice of the template name to view
fn query_template<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    template_name: &str,
) -> QueryResult {
    // only allow admins to do this
    let (_, may_addr) = check_admin(deps, viewer, permit)?;
    let my_addr_raw = may_addr.map_or_else(
        || {
            may_load::<CanonicalAddr, _>(&deps.storage, MY_ADDRESS_KEY)?
                .ok_or_else(|| StdError::generic_err("Minter contract address storage is corrupt"))
        },
        Ok,
    )?;
    let my_addr = deps.api.human_address(&my_addr_raw)?;
    let viewing_key: String = may_load(&deps.storage, MY_VIEWING_KEY)?
        .ok_or_else(|| StdError::generic_err("Minter contract's viewing key storage is corrupt"))?;
    let viewer = ViewerInfo {
        address: my_addr,
        viewing_key,
    };
    let name_key = template_name.as_bytes();
    let map_store = ReadonlyPrefixedStorage::new(PREFIX_TEMPLATE_MAP, &deps.storage);
    let idx: u16 = may_load(&map_store, name_key)?.ok_or_else(|| {
        StdError::generic_err(format!("Unknown template name: {}", template_name))
    })?;
    let idx_key = idx.to_le_bytes();
    let templ_store = ReadonlyPrefixedStorage::new(PREFIX_TEMPLATE, &deps.storage);
    let template: StoredTemplate = may_load(&templ_store, &idx_key)?
        .ok_or_else(|| StdError::generic_err("Template storage is corrupt"))?;

    to_binary(&QueryAnswer::Template {
        template: template.into_humanized(deps, &mut Vec::new(), viewer)?,
    })
}

/// Returns QueryResult displaying the admin list
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

// nft contract info used for public descriptions
#[derive(Clone)]
pub struct ContractMintInfo {
    // nft contract address
    pub address: HumanAddr,
    // collection creator
    pub creator: Option<HumanAddr>,
    // default royalty info
    pub default_royalty: Option<DisplayRoyaltyInfo>,
    // true if minting contract is authorized to mint on this nft contract
    pub minting_authorized: bool,
}

// ContractMintInfo cache entry
pub struct MintInfoCache {
    // nft contract index
    pub index: u16,
    // contract minting info
    pub info: ContractMintInfo,
}

/// Returns StdResult<Vec<PublicDescription>> listing the public descriptions of the next
/// nfts the templates will mint
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `idxs` - list of template indices to check
fn get_pub_desc<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    idxs: &[u16],
) -> StdResult<Vec<PublicDescription>> {
    let my_addr_raw: CanonicalAddr = may_load(&deps.storage, MY_ADDRESS_KEY)?
        .ok_or_else(|| StdError::generic_err("Minter contract address storage is corrupt"))?;
    let token_creator = deps.api.human_address(&my_addr_raw)?;
    let mut cache: Vec<MintInfoCache> = Vec::new();
    let mut descs: Vec<PublicDescription> = Vec::new();
    let templ_store = ReadonlyPrefixedStorage::new(PREFIX_TEMPLATE, &deps.storage);
    let contr_store = ReadonlyPrefixedStorage::new(PREFIX_CONTRACT, &deps.storage);
    for idx in idxs.iter() {
        let template: StoredTemplate = may_load(&templ_store, &idx.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Template storage is corrupt"))?;
        // if already saw this nft contract, pull the info from the cache
        let contr_info = if let Some(inf) =
            cache.iter().find(|c| c.index == template.nft_contract_idx)
        {
            inf.info.clone()
        // unseen nft contract
        } else {
            // get contract info
            let nft_raw: StoreContractInfo =
                may_load(&contr_store, &template.nft_contract_idx.to_le_bytes())?
                    .ok_or_else(|| StdError::generic_err("NFT contract info storage is corrupt"))?;
            let (nft_contract, creator) = nft_raw.into_humanized_plus(&deps.api)?;
            // get default royalty info
            let def_query_msg = Snip721QueryMsg::RoyaltyInfo { viewer: None };
            let resp: StdResult<RoyaltyInfoWrapper> = def_query_msg.query(
                &deps.querier,
                nft_contract.code_hash.clone(),
                nft_contract.address.clone(),
            );
            let default = resp.unwrap_or(RoyaltyInfoWrapper {
                royalty_info: RoyaltyInfoResponse { royalty_info: None },
            });
            // check if this contract has minting authority
            let minters_query_msg = Snip721QueryMsg::Minters {};
            let minters_resp: MintersResponse = minters_query_msg.query(
                &deps.querier,
                nft_contract.code_hash,
                nft_contract.address.clone(),
            )?;
            let inf = ContractMintInfo {
                address: nft_contract.address,
                creator,
                default_royalty: default.royalty_info.royalty_info,
                minting_authorized: minters_resp.minters.minters.contains(&token_creator),
            };
            cache.push(MintInfoCache {
                index: template.nft_contract_idx,
                info: inf.clone(),
            });
            inf
        };
        let mintable = template
            .minting_limit
            .map_or(true, |l| template.next_serial <= l)
            && contr_info.minting_authorized;
        let royalty_info = if let Some(r) = template.royalty_info {
            Some(r.to_display(&deps.api, true)?)
        } else {
            contr_info.default_royalty
        };
        let nft_info = NftDossierForListing {
            public_metadata: template.public_metadata,
            royalty_info,
            mint_run_info: MintRunInfo {
                collection_creator: contr_info.creator,
                token_creator: token_creator.clone(),
                time_of_minting: None,
                mint_run: template.mint_run,
                serial_number: template.next_serial,
                quantity_minted_this_run: template.minting_limit,
            },
        };
        descs.push(PublicDescription {
            template_name: template.name,
            nft_info,
            nft_contract_address: contr_info.address,
            mintable,
        });
    }
    Ok(descs)
}

/// Returns StdResult<Vec<u16>>
///
/// returns a list of template indexes corresponding to the optionally specified list of
/// template names
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `template_names` - optional list of template names to view
fn get_idxs<S: ReadonlyStorage>(
    storage: &S,
    template_names: Option<Vec<String>>,
) -> StdResult<Vec<u16>> {
    let state: State = load(storage, STATE_KEY)?;
    template_names.map_or_else(
        || Ok((0..state.template_cnt).collect::<Vec<u16>>()),
        |l| {
            if l.is_empty() {
                Ok((0..state.template_cnt).collect::<Vec<u16>>())
            } else {
                let map_store = ReadonlyPrefixedStorage::new(PREFIX_TEMPLATE_MAP, storage);
                l.iter()
                    .map(|n| {
                        may_load::<u16, _>(&map_store, n.as_bytes())?.ok_or_else(|| {
                            StdError::generic_err(format!("Unknown template name: {}", n))
                        })
                    })
                    .collect::<StdResult<Vec<u16>>>()
            }
        },
    )
}

/// Returns StdResult<(Option<HumanAddr>, Option<CosmosMsg>)>
///
/// stores a new nft template and returns its nft contract's address and SetViewingKey msg if
/// it is a new nft contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `state` - a mutable reference to the contract State
/// * `template` - the new nft Template
fn add_template<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    state: &mut State,
    template: Template,
) -> StdResult<(Option<HumanAddr>, Option<CosmosMsg>)> {
    let name_key = template.name.as_bytes();
    let mut map_store = PrefixedStorage::new(PREFIX_TEMPLATE_MAP, &mut deps.storage);
    if may_load::<u16, _>(&map_store, name_key)?.is_none() {
        if let Some(pub_meta) = template.public_metadata.as_ref() {
            enforce_metadata_field_exclusion(pub_meta)?;
        }
        if let Some(priv_meta) = template.private_metadata.as_ref() {
            enforce_metadata_field_exclusion(priv_meta)?;
        }
        let idx = state.template_cnt;
        save(&mut map_store, name_key, &idx)?;
        state.template_cnt = state.template_cnt.checked_add(1).ok_or_else(|| {
            StdError::generic_err("Reached the implementation limit for the number of templates")
        })?;
        let (nft_contract_idx, human, msg) =
            process_stored_contract_info(deps, state, template.nft_contract)?;
        let stored = StoredTemplate {
            name: template.name,
            public_metadata: template.public_metadata,
            private_metadata: template.private_metadata,
            royalty_info: template
                .royalty_info
                .map(|r| r.get_stored(&deps.api))
                .transpose()?,
            mint_run: 1,
            next_serial: 1,
            minting_limit: template.minting_limit,
            nft_contract_idx,
        };
        let mut templ_store = PrefixedStorage::new(PREFIX_TEMPLATE, &mut deps.storage);
        save(&mut templ_store, &idx.to_le_bytes(), &stored)?;
        return Ok((human, msg));
    }
    Err(StdError::generic_err(
        "There is already a template with that name",
    ))
}

/// Returns StdResult<(u16, Option<HumanAddr>, Option<CosmosMsg>)>
///
/// gets the index, address, and possible SetViewingKey msg of an optional ContractInfo, returning 0
/// as the default (the first ContractInfo provided), and creating, storing, and setting a viewing key
/// with a new one if needed
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `state` - a mutable reference to the contract State
/// * `contract` - the optional ContractInfo whose matching StoreContractInfo and index should be returned
fn process_stored_contract_info<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    state: &mut State,
    contract: Option<ContractInfo>,
) -> StdResult<(u16, Option<HumanAddr>, Option<CosmosMsg>)> {
    // if a ContractInfo was given, get its index or save it if it is new
    if let Some(contr) = contract {
        let mut supplied = contr.get_store(&deps.api)?;
        let contr_key = supplied.address.as_slice();
        let mut map_store = PrefixedStorage::new(PREFIX_CONTRACT_MAP, &mut deps.storage);
        let (idx, msg) = if let Some(i) = may_load::<u16, _>(&map_store, contr_key)? {
            (i, None)
        } else {
            let i = state.contract_cnt;
            state.contract_cnt = state.contract_cnt.checked_add(1).ok_or_else(|| {
                StdError::generic_err(
                    "Reached the implementation limit for the number of nft contracts",
                )
            })?;
            save(&mut map_store, contr_key, &i)?;
            let query_msg = Snip721QueryMsg::ContractCreator {};
            let resp: StdResult<Snip721ContractCreatorResponse> =
                query_msg.query(&deps.querier, contr.code_hash, contr.address.clone());
            supplied.creator = resp
                .ok()
                .map(|r| {
                    r.contract_creator
                        .creator
                        .map(|c| deps.api.canonical_address(&c))
                })
                .flatten()
                .transpose()?;
            let mut contr_store = PrefixedStorage::new(PREFIX_CONTRACT, &mut deps.storage);
            save(&mut contr_store, &i.to_le_bytes(), &supplied)?;
            let key: String = may_load(&deps.storage, MY_VIEWING_KEY)?.ok_or_else(|| {
                StdError::generic_err("Minter contract's viewing key storage is corrupt")
            })?;
            let message = Snip721HandleMsg::SetViewingKey { key }.to_cosmos_msg(
                supplied.code_hash,
                contr.address.clone(),
                None,
            )?;
            (i, Some(message))
        };
        Ok((idx, Some(contr.address), msg))
    // if a ContractInfo was not given, default to using the first nft contract
    } else {
        // if the contract does not have any nft contracts to use
        if state.contract_cnt == 0 {
            return Err(StdError::generic_err(
                "You can not create a template until you have provided at least one NFT contract",
            ));
        }
        Ok((0, None, None))
    }
}

/// Returns StdResult<()>
///
/// makes sure that Metadata does not have both `token_uri` and `extension`
///
/// # Arguments
///
/// * `metadata` - a reference to Metadata
fn enforce_metadata_field_exclusion(metadata: &Metadata) -> StdResult<()> {
    if metadata.token_uri.is_some() && metadata.extension.is_some() {
        return Err(StdError::generic_err(
            "Metadata can not have BOTH token_uri AND extension",
        ));
    }
    Ok(())
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
                cyclops_idx.insert(var_cnt);
                forced_cyclops = None;
            }
        }
        if let Some(jwl) = forced_jawless.as_deref() {
            if jwl == var_inf.name {
                jawless_idx.insert(var_cnt);
                forced_jawless = None;
            }
        }
        let var_name_key = var_inf.name.as_bytes();
        let mut var_map = PrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &cat_key], storage);
        if may_load::<u8, _>(&var_map, var_name_key)?.is_some() {
            return Err(StdError::generic_err(format!("Variant name:  {} already exists under category:  {}", var_inf.name, cat_name)));
        }
        let var = Variant {
            name: var_inf.name,
            svg: var_inf.svg,
        };
        jawed_weights.push(var_inf.jawed_weight);
        // if this is the first variant
        if var_cnt == 0 {
            if let Some(jawless) = var_inf.jawless_weight {
                jawless_weights.insert(vec![jawless]);
            }
        // already have variants
        } else {
            if let Some(jawless) = var_inf.jawless_weight {
                // can't add a jawless weight to a category that does not have them already
                jawless_weights.as_mut().ok_or_else(|| StdError::generic_err(format!("Category:  {} does not have jawless weights, but variant {} does", cat_name, var_inf.name)))?.push(jawless);
            } else if jawless_weights.is_some() {
                // must provide a jawless weight for a category that has them
                return Err(StdError::generic_err(format!("Category:  {} has jawless weights, but variant {} does not", cat_name, var_inf.name)));
            }
        }
        save(&mut var_map, var_name_key, &var_cnt)?;
        let mut var_store = PrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], storage);
        save(&mut var_store, &var_cnt.to_le_bytes(), &var)?;
        var_cnt = var_cnt.checked_add(1).ok_or_else(|| StdError::generic_err(format!("Reached maximum number of variants for category: {}", cat_name)))?;
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