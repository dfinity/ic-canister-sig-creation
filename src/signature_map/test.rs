use super::*;
use assert_matches::assert_matches;
use ic_certification::hash_tree::SubtreeLookupResult::Found;
use ic_certification::{Hash, LookupResult};
use sha2::{Digest, Sha256};

fn hash_bytes(value: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref());
    hasher.finalize().into()
}

fn seed(x: u64) -> Hash {
    hash_bytes(x.to_be_bytes())
}

fn message(x: u64) -> Hash {
    hash_bytes(x.to_le_bytes())
}

#[test]
fn test_signature_lookup() {
    let mut map = SignatureMap::default();
    map.put(&seed(1), message(1), 10);
    assert_eq!(
        map.witness(&seed(1), message(1))
            .expect("failed to get a witness")
            .digest(),
        map.root_hash()
    );
    assert!(map.witness(&seed(1), message(2)).is_none());
    assert!(map.witness(&seed(2), message(1)).is_none());

    map.delete(hash_bytes(seed(1)), message(1));
    assert!(map.witness(&seed(1), message(1)).is_none());
}

#[test]
fn test_signature_expiration() {
    let mut map = SignatureMap::default();

    map.put(&seed(1), message(1), 10);
    map.put(&seed(1), message(2), 20);
    map.put(&seed(2), message(1), 15);
    map.put(&seed(2), message(2), 25);

    assert_eq!(2, map.prune_expired(/*time now*/ 19));
    assert!(map.witness(&seed(1), message(1)).is_none());
    assert!(map.witness(&seed(2), message(1)).is_none());

    assert!(map.witness(&seed(1), message(2)).is_some());
    assert!(map.witness(&seed(2), message(2)).is_some());
}

#[test]
fn test_signature_expiration_limit() {
    let mut map = SignatureMap::default();

    for i in 0..100 {
        map.put(&seed(i), message(i), 10 + i);
    }

    assert_eq!(50, map.prune_expired(/*time now*/ 100));

    for i in 0..50 {
        assert!(map.witness(&seed(i), message(i)).is_none());
    }
    for i in 50..100 {
        assert!(map.witness(&seed(i), message(i)).is_some());
    }
}

#[test]
fn test_random_modifications() {
    use rand::prelude::*;

    let mut map = SignatureMap::default();
    let mut rng = rand::thread_rng();
    let window_size = 5;

    let mut pairs = Vec::new();

    for round in 1..100 {
        let n_seeds = rng.gen_range(0..5);
        for _i in 0..n_seeds {
            let mut seed = Hash::default();
            rng.fill_bytes(&mut seed);

            let n_messages = rng.gen_range(0..5);
            for _k in 0..n_messages {
                let mut message_hash = Hash::default();
                rng.fill_bytes(&mut message_hash);

                pairs.push((seed, message_hash));
                map.put(seed.as_slice(), message_hash, round);
            }
        }

        map.prune_expired(round.saturating_sub(window_size));

        for (k, v) in pairs.iter() {
            if let Some(witness) = map.witness(k, *v) {
                assert_eq!(
                    witness.digest(),
                    map.root_hash(),
                    "produced a bad witness: {witness:?}"
                );
            }
        }
    }
}

#[test]
fn test_signatures_pruned_on_add() {
    const TIME_NOW: u64 = 100;
    let mut map = SignatureMap::default();

    let sig_inputs = CanisterSigInputs {
        domain: b"ic-request-auth-delegation",
        seed: &[1, 2, 3],
        message: &[4, 5, 6],
    };

    for i in 0..50 {
        map.add_signature_internal(&sig_inputs, TIME_NOW + i);
    }

    assert_eq!(map.len(), 50);

    // Pruning timeout is one minute
    map.add_signature_internal(&sig_inputs, TIME_NOW + 2 * MINUTE_NS);
    assert_eq!(map.len(), 1);
}

#[test]
fn test_signature_round_trip() {
    const TIME_NOW: u64 = 100;
    let certificate = vec![1u8, 2, 3];
    let sig_inputs = CanisterSigInputs {
        domain: b"ic-request-auth-delegation",
        seed: &[1, 2, 3],
        message: &[4, 5, 6],
    };

    let mut map = SignatureMap::default();
    map.add_signature_internal(&sig_inputs, TIME_NOW);
    let result = map
        .get_signature_as_cbor_internal(&sig_inputs, certificate.clone(), None)
        .expect("failed to get signature");

    let sig: CanisterSig =
        serde_cbor::from_slice(&result).expect("failed to deserialize signature");
    assert_eq!(sig.certificate.as_slice(), certificate.as_slice());
    let Found(subtree) = sig.tree.lookup_subtree([b"sig"]) else {
        panic!("expected to find a subtree");
    };
    assert_eq!(subtree.digest(), map.root_hash());
    // canister sig path as per spec: /sig/<seed_hash>/<message_hash>
    let path: &[&[u8]] = &[b"sig", &hash_bytes(sig_inputs.seed), &sig_inputs.message_hash()];
    assert_matches!(sig.tree.lookup_path(path), LookupResult::Found(_));
}

#[test]
fn test_signature_error_non_existing() {
    let map = SignatureMap::default();

    let sig_inputs = CanisterSigInputs {
        domain: b"ic-request-auth-delegation",
        seed: &[1, 2, 3],
        message: &[4, 5, 6],
    };

    let certificate = vec![1u8, 2, 3];
    let result = map.get_signature_as_cbor_internal(&sig_inputs, certificate, None);
    assert_matches!(result, Err(CanisterSigError::NoSignature));
}
