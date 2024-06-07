# canister-sig-util

Utils crate for handling canister signatures public keys and _creating_ canister signatures.
Please refer to the [ic-standalone-sig-verifier](https://github.com/dfinity/ic/tree/master/rs/crypto/standalone-sig-verifier) crate for canister signature _verification_.

## Usage

In order to create a canister signature, a canister needs to commit to a public key seed and a  message hash in its `certified_data`. See also the official specification of [canister signatures](https://internetcomputer.org/docs/current/references/ic-interface-spec/#canister-signatures) as well as the documentation of [certified data](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-certified-data).

### Creating Signatures

Creating a signature is a two-step process:
1. the signature has to be prepared in an `update` call
2. the signature has to be retrieved in a `query` call

In order to bridge the two steps, the canister has to keep state about the prepared signatures:

```rust
thread_local! {
    /// Prepared canister signatures, no need to keep them in stable memory as they are only kept for one minute
    /// (to give clients time to do the query call).
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());
}
```

### Preparing a Signature

To prepare a signature on a message, add it's `hash` to the signature map together with the `seed` used to generate the public key:

```rust
fn add_signature(seed: &[u8], message_hash: Hash) {
    SIGNATURES.with(|sigs| {
        let mut sigs = sigs.borrow_mut();
        sigs.add_signature(seed, message_hash);
    });
}
```

Then update the `certified_data` to the new root hash of the signature map:

```rust
fn update_root_hash() {
    SIGNATURES.with_borrow(|sigs| {
        set_certified_data(&labeled_hash(LABEL_SIG, &sigs.root_hash()));
    })
}
```
### Retrieving a Signature

To retrieve a prepared signature, use the `get_signature_as_cbor` on the signature map:

```rust
fn get_signature(seed: &[u8], message_hash: Hash) -> Result<Vec<u8>, String> {
    SIGNATURES.with(|sigs| {
        let sig_map = sigs.borrow();
        sig_map.get_signature_as_cbor(seed, message_hash, None)
    });
}
```