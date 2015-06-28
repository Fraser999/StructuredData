#![forbid(bad_style, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unsigned_negation, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(dead_code)]

//! Example of proposed Structured Data for the SAFE Network.

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
