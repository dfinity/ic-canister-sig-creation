# IC Canister Signatures Creation

Crate for handling canister signatures public keys and _creating_ canister signatures.
Please refer to the [ic-standalone-sig-verifier](https://github.com/dfinity/ic/tree/master/rs/crypto/standalone-sig-verifier) crate for canister signature _verification_.

## Introduction

In order to create a canister signature, a canister needs to commit to a public key `seed` and a `message_hash` in its `certified_data`. This crate provides utilities to make this process as easy as possible.

For a more in-depth explanation of the concepts, see the official specification of [canister signatures](https://internetcomputer.org/docs/current/references/ic-interface-spec/#canister-signatures) as well as the documentation of [certified data](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-certified-data).

## Creating Signatures

Creating a signature is a two-step process:
1. the signature has to be prepared in an `update` call
2. the signature has to be retrieved in a `query` call

In order to bridge the two steps, the canister has to keep state about the prepared signatures:

```rust
use canister_sig_util::signature_map::SignatureMap;

thread_local! {
    /// Prepared canister signatures, no need to keep them in stable memory as they are only kept for one minute
    /// (to give clients time to do the query call).
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());
}
```

### Preparing a Signature

To prepare a signature on a message, add it's `hash` to the signature map together with the `seed` used to generate the public key:

```rust
use canister_sig_util::hash_bytes;

/// The signature domain should be unique for the context in which the signature is used.
const SIG_DOMAIN: &[u8] = b"ic-example-canister-sig";

fn add_signature(seed: &[u8], message: &[u8]) {
    SIGNATURES.with(|sigs| {
        let mut sigs = sigs.borrow_mut();
        sigs.add_signature(seed, &SIG_DOMAIN, message);
    });
}
```

Then update the `certified_data` to the new root hash of the signature map:

```rust
use canister_sig_util::signature_map::LABEL_SIG;
use ic_cdk::api::set_certified_data;

fn update_root_hash() {
    SIGNATURES.with_borrow(|sigs| {
        set_certified_data(&labeled_hash(LABEL_SIG, &sigs.root_hash()));
    })
}
```
### Retrieving a Signature

To retrieve a prepared signature, use the `get_signature_as_cbor` on the `SignatureMap` instance:

```rust
fn get_signature(seed: &[u8], message_hash: Hash) -> Result<Vec<u8>, String> {
    SIGNATURES.with(|sigs| {
        let sig_map = sigs.borrow();
        sig_map.get_signature_as_cbor(seed, message_hash, None)
    });
}
```