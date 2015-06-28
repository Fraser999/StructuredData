#![forbid(bad_style, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unsigned_negation, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(dead_code)]

//! # Example of Proposed Structured Data for the SAFE Network
//!
//! This is an extension of the proposed implementation described in [RFC 0000][0].  It conflicts
//! with the "Detailed Design" section, but is in alignment with the other main sections of the RFC.
//!
//! It may be helpful to view the raw source either [on GitHub][1] or [in the docs][2] while reading
//! this, since it shows all the elements together in one place.
//!
//! The main differences between the original proposal and this are:
//!
//! * Clearly-identified immutable and mutable parts
//! * Multiple versions retained in a single place
//! * No signatures retained in the `Data` element
//!
//! This proposal is slightly more complex than the original, but not largely so.  This added
//! complexity provides greater ease of use and extensibility of rules.
//!
//!
//!
//! # Authorisation of Mutating Requests
//!
//! This is more flexible than the process described in the original proposal.  The idea is that
//! each owners' public key is given a weighting.  To authorise a mutation, enough signatures must
//! be provided so that the combined weight of the corresponding public keys exceeds a limit.  The
//! limit can itself be changed via an authorised request.
//!
//! This basic system works well for a single owner (where the calculation is almost a no-op), but
//! also is fairly simple to understand in the case of multiple owners.  The rules for the network
//! to implement this are as simple as in the original proposal, and the cost in terms of data size
//! is minimal; a `u64` plus another `u64` per owner.  For a single owner, both of these elements
//! could be removed from the serialised `Data`, giving no additional cost.
//!
//! I have also not included the signatures as part of the `Data` since these only need to be
//! examined by the network at the point when the `Data` is mutated, i.e. when the request is
//! received.  This may be an oversight though, in which case they can be added where required.
//!
//!
//!
//! # Immutable Part of `Data`
//!
//! The `FixedAttributes` are immutable for the lifetime of the `Data`.  As well as the original
//! `type_tag` and `id` whose meanings are unchanged, I have added the following fields:
//!
//! * `max_versions`: self-explanatory, but the rules for handling exceeding this limit would need
//! to be decided.  An easy option would be to simply pop the oldest version.
//! * `min_retained_count`: we can archive old versions if required.  The process would need to be
//! defined, but these archived parts could become immutable and hence even stored as
//! `ImmutableData`.  At the point when the old versions are stripped out of the `Data` for
//! archiving, this field would specify how many versions to retain.  This could be just one if the
//! data type in question normally only needs the single most recent version (e.g. user's session
//! packet) or could be many if the data often uses several versions (e.g. file browser with
//! rollback capabilities).
//! * `data`: This can be used for any purpose appropriate to that particular `Data` type.
//!
//!
//!
//! # Mutable Part of `Data`
//!
//! The `MutableAttributes` can be changed if enough owners sign a request to change them.  Such a
//! request would need to also come with an incremented `Version` to avoid synchronisation issues.
//!
//! The `owner_keys` and `min_weight_for_consensus` relate to the authorisation process described
//! above.  The remaining fields are:
//!
//! * `expiry_date`: a (probably controversial!) idea to allow the `Data` to be removed from the
//! network on a given date.  This would not require exactness or an NTP server - it would be an
//! approximate time point at which the the managing nodes would remove the `Data` from their
//! records.  This isn't just to save space on the network, more that it could be a useful feature
//! for users.
//! * `data`: as per `FixedAttributes::data`.
//!
//!
//!
//! # Versions
//!
//! Another major departure from the original proposal is to hold a `Vec<Version>` rather than a
//! single one.  This would comprise the most recent versions, but may be only one if
//! `FixedAttributes::max_versions == 1` or may be all versions if total `Data` size permits.
//!
//! In at least two of our own use-cases (session packet and directory listings), we need to be able
//! to store and retrieve more than just the most recent version.  This can be done in the original
//! proposal by serialising this information into the single `data` field, but this proposal makes
//! that task more obvious and less error-prone.
//!
//! Furthermore, by exposing the versions in this way, it leaves scope for the network to be able to
//! handle archiving old versions without any client interaction.  This wouldn't be possible if the
//!  network weren't able to access the list of versions, as is the case in the original proposal.
//!
//! The `Version` struct comprises two elements:
//!
//! * `index`: This will be an incrementing value.  To maintain simplicity we can enforce a strict
//! increment-by-one policy, i.e. if a new version arrives out of sequence it will be rejected.
//! However, this isn't an issue as long as the client has to send the entire `Data` every time a
//! mutation is made.  We can look at re-implementing the branching protocol as per the
//! `StructuredDataVersions` from the C++ codebase, but I don't think that was a popular class.
//! * `data`: per-version arbitrary data.
//!
//!
//!
//! # General
//!
//! There would still be a hard upper limit on the total size of a `Data` instance as described in
//! the original proposal.
//!
//! While some of the rules can be ignored in the initial implementation of this (e.g. handling
//! archiving) I don't envisage this being more difficult to implement than the original proposal.
//! This also leaves room for eventual improvement in efficiency, for example by allowing clients to
//! send only a new `Version` rather than always sending a full `Data` packet.
//!
//!
//!
//! [0]: https://github.com/maidsafe/rfcs/pull/11/files "SAFE Network RFC 0000"
//! [1]: https://github.com/Fraser999/StructuredData/blob/master/src/structured_data.rs
//! "Raw source for Structured Data on GitHub"
//! [2]: http://fraser999.github.io/StructuredData/src/structured_data/structured_data.rs.html
//! "Raw source for Structured Data in the docs"


extern crate routing;
extern crate sodiumoxide;
extern crate time;

/// Structured Data implementation.
pub mod structured_data;

use routing::NameType;
use sodiumoxide::crypto::sign;
use structured_data::{Data, FixedAttributes, KeyAndWeight, MutableAttributes, Version};

type StructuredData = Data;

fn main() {
    let mut user_session_packet = StructuredData {
        fixed_attributes: FixedAttributes {
            type_tag: 1,
            id: NameType::new([0u8; 64]),
            max_versions: 10,
            min_retained_count: 5,
            data: vec!['A' as u8, 'B' as u8, 'C' as u8]
        },
        mutable_attributes: MutableAttributes {
            owner_keys: vec![
                KeyAndWeight {
                    key: sign::gen_keypair().0,
                    weight: 1
                }
            ],
            min_weight_for_consensus: 0,
            expiry_date: time::now() + time::Duration::days(36524),
            data: vec!['D' as u8, 'E' as u8, 'F' as u8]
        },
        versions: vec![
            Version {
                index: 0,
                data: vec!['v' as u8, '0' as u8]
            }
        ]
    };
    println!("user_session_packet:\n{:?}", user_session_packet);

    user_session_packet.versions.push(Version{ index: 1, data: vec!['v' as u8, '1' as u8] });
    println!("user_session_packet:\n{:?}", user_session_packet);
}
