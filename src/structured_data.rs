use std::fmt;

use routing::NameType;
use sodiumoxide::crypto::sign;
use time;

/// Top-level type: a representation of "Structured Data".
#[derive(Debug)]
pub struct Data {
    /// Immutable attributes which apply to the entire `Data` instance.
    pub fixed_attributes: FixedAttributes,
    /// Attributes which apply to the entire `Data` instance, but which can be changed with proper
    /// authorisation.
    pub mutable_attributes: MutableAttributes,
    /// The most recent (which could encompass all) versions of the `Data` instance.  Cannot be
    /// empty.
    pub versions: Vec<Version>,
}

/// Attributes of the `Data` which can never change once initially set.  These define the identity,
/// type and some of the rules the network will employ for handling the `Data`.  It can also hold
/// arbitrary data which will likely be meaningless to the network.
#[derive(Debug)]
pub struct FixedAttributes {
    /// Identifier of the `Data` type.
    pub type_tag: u64,
    /// Identity of the piece of `Data`.
    pub id: NameType,
    /// Maximum number of versions allowed.
    pub max_versions: u64,
    /// Number of versions to retain when archiving a "full" piece of `Data` (minimum value of 1).
    pub min_retained_count: u8,
    /// Arbitrary, immutable, `Data`-wide information.  May be empty.
    pub data: Vec<u8>,
}

/// A representation of an owner's public key and the bias which should be given to that key when
/// a mutating request is received by the network.
pub struct KeyAndWeight {
    /// Owner's public key.
    pub key: sign::PublicKey,
    /// Bias given to this public key (minimum value of 1).
    pub weight: u64
}

impl fmt::Debug for KeyAndWeight {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "key: {:?}, weight: {}", self.key.0, self.weight)
    }
}

/// Attributes of the `Data` which can be changed via a properly-authorised request to the network.
/// These define the current owner's public keys, further rules the network will employ for handling
/// the `Data` and also arbitrary data which will likely be meaningless to the network.
#[derive(Debug)]
pub struct MutableAttributes {
    /// Current owner or owners' public keys.  Cannot be empty.
    pub owner_keys: Vec<KeyAndWeight>,
    /// Minimum total weight of signatories' keys to allow a mutation of the piece of `Data` (at
    /// least one signature will be required regardless of this minimum).
    pub min_weight_for_consensus: u64,
    /// Coarse-grained expiry date around which time the piece of `Data` will be removed from the
    /// network.
    pub expiry_date: time::Tm,
    /// Arbitrary, mutable, `Data`-wide information.  May be empty.
    pub data: Vec<u8>,
}

/// A representation of a single version.  The `index` allows provision of strict total ordering of
/// the `Version`s.  It can also hold arbitrary data specific to that particular `Version`, e.g.
/// encrypted content or the name of a piece of "Immutable Data".
#[derive(Debug)]
pub struct Version {
    /// Sequential number to provide strict total order of versions.
    pub index: u64,
    /// Arbitrary, version-specific information.  May be empty.
    pub data: Vec<u8>,
}
