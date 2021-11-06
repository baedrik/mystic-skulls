use crate::state::{may_load, save};
use cosmwasm_std::{ReadonlyStorage, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use serde::{de::DeserializeOwned, Serialize};
use std::cmp::min;
use std::marker::PhantomData;

/// prefix for storage of the item count
pub const PREFIX_COUNT: &[u8] = b"count";
/// prefix for storage of the items
pub const PREFIX_ITEMS: &[u8] = b"items";

/// A trait marking types that can be stored in the registry by defining a function to derive
/// a storage key
pub trait AsKey {
    fn as_key(&self) -> &[u8];
}

/// item registry
pub struct Registry<'a, T: Serialize + DeserializeOwned + AsKey> {
    /// storage key for this registry
    pub reg_key: &'a [u8],
    /// storage key for the count
    pub count_key: Vec<u8>,
    /// storage key for the items
    pub items_key: Vec<u8>,
    /// item count
    pub count: u16,
    /// compiler marker
    pub _marker: PhantomData<*const T>,
}

impl<'a, T: Serialize + DeserializeOwned + AsKey> Registry<'a, T> {
    /// Returns StdResult<Registry>
    ///
    /// creates a new Registry by loading it from storage or creating a new one
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `reg_key` - the key for this registry
    pub fn new<S: ReadonlyStorage>(storage: &S, reg_key: &'a [u8]) -> StdResult<Self> {
        let mut count_key: Vec<u8> = Vec::new();
        count_key.extend_from_slice(reg_key);
        count_key.extend_from_slice(PREFIX_COUNT);
        let mut items_key: Vec<u8> = Vec::new();
        items_key.extend_from_slice(reg_key);
        items_key.extend_from_slice(PREFIX_ITEMS);
        let count: u16 = may_load(storage, &count_key)?.unwrap_or(0);
        Ok(Registry {
            reg_key,
            count_key,
            items_key,
            count,
            _marker: PhantomData,
        })
    }

    /// Returns StdResult<bool>
    ///
    /// adds an item to the registry and returns true if it was not already in the registry
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    /// * `item` - a reference to the item to add to the registry
    /// * `save_count` - true if the count should be saved
    pub fn add<S: Storage>(
        &mut self,
        storage: &mut S,
        item: &T,
        save_count: bool,
    ) -> StdResult<bool> {
        let item_key = item.as_key();
        let mut reg_store = PrefixedStorage::new(self.reg_key, storage);
        let mut added = false;
        if may_load::<u16, _>(&reg_store, item_key)?.is_none() {
            save(&mut reg_store, item_key, &self.count)?;
            let mut item_store = PrefixedStorage::new(&self.items_key, storage);
            save(&mut item_store, &self.count.to_le_bytes(), item)?;
            self.count += 1;
            if save_count {
                save(storage, &self.count_key, &self.count)?;
            }
            added = true;
        }
        Ok(added)
    }

    /// Returns StdResult<()>
    ///
    /// saves the registry count
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    pub fn save<S: Storage>(&self, storage: &mut S) -> StdResult<()> {
        save(storage, &self.count_key, &self.count)
    }

    /// Returns StdResult<u16>
    ///
    /// returns the index of the item_key if it is in the registry
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `item_key` - a reference to the key of the item to check
    pub fn self_get_idx<S: ReadonlyStorage>(&self, storage: &S, item_key: &[u8]) -> StdResult<u16> {
        Registry::<T>::get_idx(storage, item_key, self.reg_key)
    }

    /// Returns StdResult<u16>
    ///
    /// returns the index of the item_key if it is in a registry with the specified key
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `item_key` - a reference to the key of the item to check
    /// * `key` - the key for the registry in question
    pub fn get_idx<S: ReadonlyStorage>(storage: &S, item_key: &[u8], key: &[u8]) -> StdResult<u16> {
        let reg_store = ReadonlyPrefixedStorage::new(key, storage);
        may_load::<u16, _>(&reg_store, item_key)?.ok_or_else(|| {
            StdError::generic_err("Attempting to get_idx of item not in the registry")
        })
    }

    /// Returns StdResult<(u16, Vec<T>)>
    ///
    /// displays the count and the list of items with pagination
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `page` - page number to start display
    /// * `page_size` - number of items to display
    pub fn display<S: ReadonlyStorage>(
        &self,
        storage: &S,
        page: u16,
        page_size: u16,
    ) -> StdResult<(u16, Vec<T>)> {
        let start = page * page_size;
        let end = min(start + page_size, self.count);
        let mut list: Vec<T> = Vec::new();
        let item_store = ReadonlyPrefixedStorage::new(&self.items_key, storage);
        for idx in start..end {
            if let Some(item) = may_load::<T, _>(&item_store, &idx.to_le_bytes())? {
                list.push(item);
            }
        }
        Ok((self.count, list))
    }

    /// Returns StdResult<T>
    ///
    /// returns the item at the specified index in this registry
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `idx` - index of item to return
    pub fn self_get_at<S: ReadonlyStorage>(&self, storage: &S, idx: u16) -> StdResult<T> {
        Registry::<T>::get_at(storage, idx, self.reg_key)
    }

    /// Returns StdResult<T>
    ///
    /// returns the item at the specified index in the specified registry
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `idx` - index of item to return
    /// * `key` - the key for the registry
    pub fn get_at<S: ReadonlyStorage>(storage: &S, idx: u16, key: &[u8]) -> StdResult<T> {
        let mut items_key: Vec<u8> = Vec::new();
        items_key.extend_from_slice(key);
        items_key.extend_from_slice(PREFIX_ITEMS);
        let item_store = ReadonlyPrefixedStorage::new(&items_key, storage);
        may_load::<T, _>(&item_store, &idx.to_le_bytes())?.ok_or_else(|| {
            StdError::generic_err("Attempting to retrieve a registry item at an invalid index")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{testing::*, HumanAddr};

    use crate::contract_info::{ContractInfo, StoreContractInfo};

    #[test]
    fn test_registry() {
        pub const PREFIX_TEST_CONTRACT: &[u8] = b"contract";
        let mut deps = mock_dependencies(20, &[]);

        // test with ContractInfos
        let mut contract_registry = Registry::new(&deps.storage, PREFIX_TEST_CONTRACT).unwrap();

        let contract1 = ContractInfo {
            address: HumanAddr::from("contract 1".to_string()),
            code_hash: "hash1".to_string(),
        };
        let raw1 = contract1.get_store(&deps.api).unwrap();
        let contract2 = ContractInfo {
            address: HumanAddr::from("contract 2".to_string()),
            code_hash: "hash2".to_string(),
        };
        let raw2 = contract2.get_store(&deps.api).unwrap();
        let contract3 = ContractInfo {
            address: HumanAddr::from("contract 3".to_string()),
            code_hash: "hash3".to_string(),
        };
        let raw3 = contract3.get_store(&deps.api).unwrap();

        // test displaying an empty list
        let (_count, display) = contract_registry.display(&deps.storage, 0, 100).unwrap();
        assert_eq!(display, Vec::new());
        // add raw1
        let _result = contract_registry.add(&mut deps.storage, &raw1, true);
        // test displaying just one in the list
        let (count, display) = contract_registry.display(&deps.storage, 0, 100).unwrap();
        assert_eq!(display, vec![raw1.clone()]);
        assert_eq!(count, 1);
        // test displaying after the only one in the list
        let (_count, display) = contract_registry.display(&deps.storage, 1, 100).unwrap();
        assert_eq!(display, Vec::new());
        // add raw2
        let _result = contract_registry.add(&mut deps.storage, &raw2, true);
        let (count, display) = contract_registry.display(&deps.storage, 0, 100).unwrap();
        assert_eq!(display, vec![raw1.clone(), raw2.clone()]);
        assert_eq!(count, 2);
        assert_eq!(
            contract_registry
                .self_get_idx(&deps.storage, raw1.address.as_slice())
                .unwrap(),
            0u16
        );
        assert_eq!(
            contract_registry
                .self_get_idx(&deps.storage, raw2.address.as_slice())
                .unwrap(),
            1u16
        );
        assert!(contract_registry
            .self_get_idx(&deps.storage, raw3.address.as_slice())
            .is_err());
        assert_eq!(
            Registry::<StoreContractInfo>::get_idx(
                &deps.storage,
                raw1.address.as_slice(),
                PREFIX_TEST_CONTRACT
            )
            .unwrap(),
            0u16
        );
        assert_eq!(
            Registry::<StoreContractInfo>::get_idx(
                &deps.storage,
                raw2.address.as_slice(),
                PREFIX_TEST_CONTRACT
            )
            .unwrap(),
            1u16
        );
        assert!(Registry::<StoreContractInfo>::get_idx(
            &deps.storage,
            raw3.address.as_slice(),
            PREFIX_TEST_CONTRACT
        )
        .is_err());
        // test adding raw1 when it is already in the registry
        let result = contract_registry.add(&mut deps.storage, &raw1, true);
        assert!(result.is_ok());
        // list should not have changed
        let (count, display) = contract_registry.display(&deps.storage, 0, 100).unwrap();
        assert_eq!(display, vec![raw1.clone(), raw2.clone()]);
        assert_eq!(count, 2);
        // test display with page_size 0
        let (_count, display) = contract_registry.display(&deps.storage, 0, 0).unwrap();
        assert_eq!(display, Vec::new());
        // test display just one the last item
        let (count, display) = contract_registry.display(&deps.storage, 1, 1).unwrap();
        assert_eq!(display, vec![raw2.clone()]);
        assert_eq!(count, 2);
        // add raw3
        let _result = contract_registry.add(&mut deps.storage, &raw3, true);
        let (count, display) = contract_registry.display(&deps.storage, 0, 100).unwrap();
        assert_eq!(display, vec![raw1.clone(), raw2.clone(), raw3.clone(),]);
        assert_eq!(count, 3);
        assert_eq!(
            contract_registry
                .self_get_idx(&deps.storage, raw3.address.as_slice())
                .unwrap(),
            2u16
        );
        assert_eq!(
            Registry::<StoreContractInfo>::get_idx(
                &deps.storage,
                raw3.address.as_slice(),
                PREFIX_TEST_CONTRACT
            )
            .unwrap(),
            2u16
        );
        // test valid get_at
        assert_eq!(
            contract_registry.self_get_at(&deps.storage, 1u16).unwrap(),
            raw2.clone()
        );
        // test bad index
        assert!(contract_registry.self_get_at(&deps.storage, 10u16).is_err());
        // test valid get_at
        assert_eq!(
            Registry::<StoreContractInfo>::get_at(&deps.storage, 2u16, PREFIX_TEST_CONTRACT)
                .unwrap(),
            raw3.clone()
        );
        // test bad index
        assert!(
            Registry::<StoreContractInfo>::get_at(&deps.storage, 3u16, PREFIX_TEST_CONTRACT)
                .is_err()
        );
        // display the middle
        let (_count, display) = contract_registry.display(&deps.storage, 1, 1).unwrap();
        assert_eq!(display, vec![raw2.clone()]);
    }
}
