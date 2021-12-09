use cosmwasm_std::{Api, CanonicalAddr, HumanAddr, StdResult};
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// admins in addition to the instantiator
    pub admins: Option<Vec<HumanAddr>>,
    /// list of keyphrases
    pub keyphrases: Option<Vec<Keyphrase>>,
    /// entropy used for prng seed
    pub entropy: String,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// attempt to solve a puzzle
    Solve {
        ///proposed solution
        solution: Keyphrase,
    },
    /// add keyphrases
    AddKeyphrases {
        /// list of keyphrases to add
        keyphrases: Vec<Keyphrase>,
    },
    /// remove keyphrases (only really needed if input was erroneous)
    RemoveKeyphrases {
        /// list of puzzle IDs of the keyphrases to remove
        keyphrases: Vec<String>,
    },
    /// Create a viewing key
    CreateViewingKey { entropy: String },
    /// Set a viewing key
    SetViewingKey {
        key: String,
        // optional padding can be used so message length doesn't betray key length
        padding: Option<String>,
    },
    /// allows an admin to add more admins
    AddAdmins {
        /// list of address to grant admin priveleges
        admins: Vec<HumanAddr>,
    },
    /// allows an admin to remove admin addresses
    RemoveAdmins {
        /// list of address to revoke admin priveleges from
        admins: Vec<HumanAddr>,
    },
    /// disallow the use of a permit
    RevokePermit {
        /// name of the permit that is no longer valid
        permit_name: String,
    },
}

/// Responses from handle functions
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    /// response of both AddAdmins and RemoveAdmins
    AdminsList {
        /// current admins
        admins: Vec<HumanAddr>,
    },
    /// response from creating a viewing key
    ViewingKey {
        key: String,
    },
    RevokePermit {
        status: String,
    },
    /// list of keyphrases
    KeyphraseList {
        keyphrases: Vec<Keyphrase>,
    },
    /// response from attempting to solve a puzzle
    Solve {
        result: SolveResponse,
    },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the puzzles that have been solved
    Solved {},
    /// display the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the winners
    Winners {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays if the input answer is correct for a puzzle that has already been solved
    Verify {
        ///proposed solution
        solution: Keyphrase,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// displays the admins list
    Admins {
        /// current admin list
        admins: Vec<HumanAddr>,
    },
    /// list of already solved puzzles
    Solved {
        /// puzzle ids that have been solved
        puzzles: Vec<String>,
    },
    /// list of winners
    Winners {
        /// winners list
        winners: Vec<Winner>,
    },
    /// displays if the input answer is correct for a puzzle that has already been solved
    Verify {
        ///correctness check
        grade: SolveResponse,
    },
}

/// keyphrase and puzzle id
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Keyphrase {
    /// puzzle id
    pub puzzle: String,
    /// sanitized keyphrase
    pub keyphrase: String,
}

/// puzzle winner
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Winner {
    /// keyphrase
    pub puzzle_info: Keyphrase,
    /// winner's address
    pub winner: Option<HumanAddr>,
}

impl Winner {
    /// Returns StdResult<StoredWinner> from converting a Winner to a StoredWinner
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn into_store<A: Api>(self, api: &A) -> StdResult<StoredWinner> {
        Ok(StoredWinner {
            puzzle_info: self.puzzle_info,
            winner: self.winner.map(|h| api.canonical_address(&h)).transpose()?,
        })
    }
}

/// puzzle winner in storage
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoredWinner {
    /// keyphrase
    pub puzzle_info: Keyphrase,
    /// winner's address
    pub winner: Option<CanonicalAddr>,
}

impl StoredWinner {
    /// Returns StdResult<Winner> from converting a StoredWinner to a Winner
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn into_human<A: Api>(self, api: &A) -> StdResult<Winner> {
        Ok(Winner {
            puzzle_info: self.puzzle_info,
            winner: self.winner.map(|c| api.human_address(&c)).transpose()?,
        })
    }
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SolveResponse {
    Winner,
    WrongAnswer,
    AlreadySolved,
    Correct,
}
