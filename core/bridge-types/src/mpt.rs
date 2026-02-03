// SPDX-License-Identifier: MIT
//! Minimal MPT (Merkle Patricia Trie) proof verification for EIP-1186 proofs.
//!
//! Verifies Ethereum state proofs against a known state root, using only
//! `alloy_primitives::keccak256` (already available in the guest).

use alloy_primitives::keccak256;

/// Errors that can occur during MPT proof verification.
#[derive(Debug)]
pub enum MptError {
    InvalidRlp(&'static str),
    InvalidProof(&'static str),
}

impl std::fmt::Display for MptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MptError::InvalidRlp(msg) => write!(f, "invalid RLP: {msg}"),
            MptError::InvalidProof(msg) => write!(f, "invalid proof: {msg}"),
        }
    }
}

impl std::error::Error for MptError {}

/// Keccak256(RLP("")): the storage root for an empty Merkle Patricia Trie.
///
/// This is used as the canonical "empty storage trie" root.
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

// --- Minimal RLP decoder ---

/// Decode a single RLP item, returning (data, rest).
/// For strings: data is the payload bytes.
/// For lists: data is the concatenated encoded items within the list.
fn rlp_decode(input: &[u8]) -> Result<(&[u8], &[u8]), MptError> {
    if input.is_empty() {
        return Err(MptError::InvalidRlp("empty input"));
    }

    let prefix = input[0];
    match prefix {
        // Single byte [0x00, 0x7f]
        0x00..=0x7f => Ok((&input[..1], &input[1..])),

        // Short string [0x80, 0xb7]: length = prefix - 0x80
        0x80..=0xb7 => {
            let len = (prefix - 0x80) as usize;
            if input.len() < 1 + len {
                return Err(MptError::InvalidRlp("short string truncated"));
            }
            Ok((&input[1..1 + len], &input[1 + len..]))
        }

        // Long string [0xb8, 0xbf]: next (prefix - 0xb7) bytes are the length
        0xb8..=0xbf => {
            let len_of_len = (prefix - 0xb7) as usize;
            if input.len() < 1 + len_of_len {
                return Err(MptError::InvalidRlp("long string length truncated"));
            }
            let len = read_be_uint(&input[1..1 + len_of_len]);
            if input.len() < 1 + len_of_len + len {
                return Err(MptError::InvalidRlp("long string data truncated"));
            }
            Ok((
                &input[1 + len_of_len..1 + len_of_len + len],
                &input[1 + len_of_len + len..],
            ))
        }

        // Short list [0xc0, 0xf7]: length = prefix - 0xc0
        0xc0..=0xf7 => {
            let len = (prefix - 0xc0) as usize;
            if input.len() < 1 + len {
                return Err(MptError::InvalidRlp("short list truncated"));
            }
            Ok((&input[1..1 + len], &input[1 + len..]))
        }

        // Long list [0xf8, 0xff]: next (prefix - 0xf7) bytes are the length
        0xf8..=0xff => {
            let len_of_len = (prefix - 0xf7) as usize;
            if input.len() < 1 + len_of_len {
                return Err(MptError::InvalidRlp("long list length truncated"));
            }
            let len = read_be_uint(&input[1..1 + len_of_len]);
            if input.len() < 1 + len_of_len + len {
                return Err(MptError::InvalidRlp("long list data truncated"));
            }
            Ok((
                &input[1 + len_of_len..1 + len_of_len + len],
                &input[1 + len_of_len + len..],
            ))
        }
    }
}

/// Check if the first RLP item is a list (vs a string).
fn rlp_is_list(input: &[u8]) -> bool {
    !input.is_empty() && input[0] >= 0xc0
}

/// Decode all items in an RLP list payload (the inner bytes after list header).
fn rlp_decode_list(list_payload: &[u8]) -> Result<Vec<&[u8]>, MptError> {
    let mut items = Vec::new();
    let mut rest = list_payload;
    while !rest.is_empty() {
        // We need to get the raw encoded item to split correctly.
        // But rlp_decode returns the *decoded* payload. For list iteration
        // we call rlp_decode on the remaining bytes.
        let (item, remainder) = rlp_decode(rest)?;
        items.push(item);
        rest = remainder;
    }
    Ok(items)
}

/// Read a big-endian unsigned integer from bytes (up to 8 bytes).
fn read_be_uint(bytes: &[u8]) -> usize {
    let mut result = 0usize;
    for &b in bytes {
        result = (result << 8) | (b as usize);
    }
    result
}

/// Convert a byte to its two nibbles.
fn byte_to_nibbles(b: u8) -> (u8, u8) {
    (b >> 4, b & 0x0f)
}

/// Compact (hex-prefix) encoding to nibbles.
/// Returns (nibbles, is_leaf).
fn compact_to_nibbles(compact: &[u8]) -> Result<(Vec<u8>, bool), MptError> {
    if compact.is_empty() {
        return Err(MptError::InvalidRlp("empty compact encoding"));
    }

    let (high, low) = byte_to_nibbles(compact[0]);
    let is_leaf = high >= 2;
    let odd = (high & 1) == 1;

    let mut nibbles = Vec::new();
    if odd {
        nibbles.push(low);
    }
    for &b in &compact[1..] {
        let (h, l) = byte_to_nibbles(b);
        nibbles.push(h);
        nibbles.push(l);
    }

    Ok((nibbles, is_leaf))
}

/// Convert a key (bytes) into nibbles for trie traversal.
fn key_to_nibbles(key: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(key.len() * 2);
    for &b in key {
        let (h, l) = byte_to_nibbles(b);
        nibbles.push(h);
        nibbles.push(l);
    }
    nibbles
}

/// Verify an MPT proof.
///
/// Given a trie `root`, a `key` (pre-hashed for the trie), and a list of
/// `proof_nodes` (RLP-encoded trie nodes from root to leaf), returns the
/// proven value bytes, or an empty vec if the key is absent.
pub fn verify_mpt_proof(
    root: [u8; 32],
    key: &[u8],
    proof_nodes: &[Vec<u8>],
) -> Result<Vec<u8>, MptError> {
    let nibbles = key_to_nibbles(key);
    let mut nibble_idx = 0;
    let mut expected_ptr = root.to_vec();

    for (i, node_rlp) in proof_nodes.iter().enumerate() {
        // Verify node matches expected pointer
        if expected_ptr.len() == 32 {
            // Standard pointer: hash of the node
            let node_hash: [u8; 32] = keccak256(node_rlp).0;
            if node_hash.as_slice() != expected_ptr.as_slice() {
                return Err(MptError::InvalidProof("node hash mismatch"));
            }
        } else {
            // Inline pointer: the node RLP itself
            if node_rlp != &expected_ptr {
                return Err(MptError::InvalidProof("inline node mismatch"));
            }
        }

        if !rlp_is_list(node_rlp) {
            return Err(MptError::InvalidProof("node is not an RLP list"));
        }

        let (list_payload, _) = rlp_decode(node_rlp)?;
        let items = rlp_decode_list(list_payload)?;

        match items.len() {
            // Branch node: 17 items (16 children + value)
            17 => {
                if nibble_idx >= nibbles.len() {
                    // We're at the end of the key, value is in items[16]
                    if i == proof_nodes.len() - 1 {
                        return Ok(items[16].to_vec());
                    }
                    return Err(MptError::InvalidProof("unexpected branch at end of key"));
                }
                let child_idx = nibbles[nibble_idx] as usize;
                nibble_idx += 1;

                if i == proof_nodes.len() - 1 {
                    // Last proof node but we still have key nibbles
                    // The child should be empty (key not in trie)
                    if items[child_idx].is_empty() {
                        return Ok(Vec::new());
                    }
                    return Err(MptError::InvalidProof(
                        "proof ends at branch but child is not empty",
                    ));
                }

                // Set expected pointer for next node
                if items[child_idx].is_empty() {
                    // Empty child means key not in trie
                    return Ok(Vec::new());
                }
                expected_ptr = items[child_idx].to_vec();
            }

            // Extension or Leaf node: 2 items (partial key + value/hash)
            2 => {
                let (partial_nibbles, is_leaf) = compact_to_nibbles(items[0])?;

                // Check that partial key matches our remaining key
                let remaining = &nibbles[nibble_idx..];
                if remaining.len() < partial_nibbles.len() {
                    // Key doesn't match this path
                    return Ok(Vec::new());
                }
                if remaining[..partial_nibbles.len()] != partial_nibbles[..] {
                    // Key diverges from this path
                    return Ok(Vec::new());
                }

                nibble_idx += partial_nibbles.len();

                if is_leaf {
                    if nibble_idx != nibbles.len() {
                        // Leaf doesn't match full key
                        return Ok(Vec::new());
                    }
                    // items[1] is the RLP-encoded value
                    return Ok(items[1].to_vec());
                }

                // Extension node: items[1] is hash (or inline RLP) of next node
                if i == proof_nodes.len() - 1 {
                    return Err(MptError::InvalidProof("proof ends at extension node"));
                }

                expected_ptr = items[1].to_vec();
            }

            _ => {
                return Err(MptError::InvalidProof(
                    "node has unexpected number of items",
                ));
            }
        }
    }

    // An empty proof is only valid for an empty trie root. Otherwise it would allow a prover to
    // "prove absence" without providing any authenticated path data.
    if proof_nodes.is_empty() {
        if root == EMPTY_TRIE_ROOT {
            return Ok(Vec::new());
        }
        return Err(MptError::InvalidProof("empty proof for non-empty root"));
    }

    Err(MptError::InvalidProof("proof did not resolve"))
}

/// Proven account data extracted from an RLP-encoded account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenAccount {
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// Verify an account proof against a state root.
///
/// The key in the state trie is `keccak256(address)`.
/// The value is RLP-encoded `[nonce, balance, storage_root, code_hash]`.
pub fn verify_account_proof(
    state_root: [u8; 32],
    address: &[u8; 20],
    account_proof: &[Vec<u8>],
) -> Result<Option<ProvenAccount>, MptError> {
    let key = keccak256(address);
    let value = verify_mpt_proof(state_root, key.as_slice(), account_proof)?;

    if value.is_empty() {
        return Ok(None);
    }

    // The value returned by verify_mpt_proof is the raw RLP list of the account
    // (e.g. starts with 0xf8). We must unwrap this list to get the field data.
    let (list_payload, remainder) = rlp_decode(&value)?;
    if !remainder.is_empty() {
        return Err(MptError::InvalidRlp("trailing bytes after account list"));
    }
    let items = rlp_decode_list(list_payload)?;

    if items.len() != 4 {
        return Err(MptError::InvalidRlp("account must have 4 fields"));
    }

    // Nonce
    let nonce = if items[0].is_empty() {
        0u64
    } else {
        read_be_uint(items[0]) as u64
    };

    // Balance (big-endian, up to 32 bytes)
    let mut balance = [0u8; 32];
    if !items[1].is_empty() {
        let offset = 32 - items[1].len();
        balance[offset..].copy_from_slice(items[1]);
    }

    // Storage root (32 bytes)
    let mut storage_root = [0u8; 32];
    if items[2].len() != 32 {
        return Err(MptError::InvalidRlp("storage_root must be 32 bytes"));
    }
    storage_root.copy_from_slice(items[2]);

    // Code hash (32 bytes)
    let mut code_hash = [0u8; 32];
    if items[3].len() != 32 {
        return Err(MptError::InvalidRlp("code_hash must be 32 bytes"));
    }
    code_hash.copy_from_slice(items[3]);

    Ok(Some(ProvenAccount {
        nonce,
        balance,
        storage_root,
        code_hash,
    }))
}

/// Verify a storage proof against a storage root.
///
/// The key in the storage trie is `keccak256(slot)` (where slot is 32-byte big-endian).
/// The value is RLP-encoded U256.
pub fn verify_storage_proof(
    storage_root: [u8; 32],
    slot: &[u8; 32],
    storage_proof: &[Vec<u8>],
) -> Result<[u8; 32], MptError> {
    // Empty trie root means all slots are zero.
    if storage_root == EMPTY_TRIE_ROOT {
        return Ok([0u8; 32]);
    }

    let key = keccak256(slot);
    let value = verify_mpt_proof(storage_root, key.as_slice(), storage_proof)?;

    if value.is_empty() {
        return Ok([0u8; 32]);
    }

    // The value from the trie is the RLP-encoded storage value.
    // Decode the RLP wrapper to get the raw big-endian bytes.
    let (raw_value, _) = rlp_decode(&value)?;
    if raw_value.is_empty() {
        return Ok([0u8; 32]);
    }
    if raw_value.len() > 32 {
        return Err(MptError::InvalidProof("storage value exceeds 32 bytes"));
    }
    let mut result = [0u8; 32];
    let offset = 32 - raw_value.len();
    result[offset..].copy_from_slice(raw_value);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_decode_single_byte() {
        let (data, rest) = rlp_decode(&[0x42]).unwrap();
        assert_eq!(data, &[0x42]);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_rlp_decode_short_string() {
        // RLP of "dog" = [0x83, 0x64, 0x6f, 0x67]
        let input = [0x83, 0x64, 0x6f, 0x67];
        let (data, rest) = rlp_decode(&input).unwrap();
        assert_eq!(data, b"dog");
        assert!(rest.is_empty());
    }

    #[test]
    fn test_rlp_decode_empty_string() {
        let (data, rest) = rlp_decode(&[0x80]).unwrap();
        assert!(data.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_rlp_decode_empty_list() {
        let (data, rest) = rlp_decode(&[0xc0]).unwrap();
        assert!(data.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_rlp_decode_short_list() {
        // List containing ["cat", "dog"]
        // cat = 0x83 0x63 0x61 0x74
        // dog = 0x83 0x64 0x6f 0x67
        // list payload = 8 bytes, so prefix = 0xc0 + 8 = 0xc8
        let input = [0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67];
        let (list_payload, rest) = rlp_decode(&input).unwrap();
        assert!(rest.is_empty());

        let items = rlp_decode_list(list_payload).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], b"cat");
        assert_eq!(items[1], b"dog");
    }

    #[test]
    fn test_compact_to_nibbles_even_extension() {
        // 0x00 prefix = even extension
        let (nibbles, is_leaf) = compact_to_nibbles(&[0x00, 0x12, 0x34]).unwrap();
        assert!(!is_leaf);
        assert_eq!(nibbles, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_compact_to_nibbles_odd_extension() {
        // 0x1X prefix = odd extension, first nibble is X
        let (nibbles, is_leaf) = compact_to_nibbles(&[0x11, 0x23]).unwrap();
        assert!(!is_leaf);
        assert_eq!(nibbles, vec![1, 2, 3]);
    }

    #[test]
    fn test_compact_to_nibbles_even_leaf() {
        // 0x20 prefix = even leaf
        let (nibbles, is_leaf) = compact_to_nibbles(&[0x20, 0xab]).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb]);
    }

    #[test]
    fn test_compact_to_nibbles_odd_leaf() {
        // 0x3X prefix = odd leaf, first nibble is X
        let (nibbles, is_leaf) = compact_to_nibbles(&[0x3a, 0xbc]).unwrap();
        assert!(is_leaf);
        assert_eq!(nibbles, vec![0xa, 0xb, 0xc]);
    }

    #[test]
    fn test_key_to_nibbles() {
        assert_eq!(key_to_nibbles(&[0xab, 0xcd]), vec![0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn test_verify_mpt_proof_simple_leaf() {
        // Construct a trivial single-leaf trie.
        // Key: keccak256 of some address (we'll use the nibbles directly)
        // Value: some bytes
        //
        // A leaf node: RLP([compact_key, value])
        // For a leaf with full 64 nibbles of key 0x0000...00 and value 0x1234:
        //   compact = 0x20 followed by 32 zero bytes (even leaf, 64 nibbles)
        //   value = [0x12, 0x34]

        // Build the leaf RLP
        let compact_key = {
            let mut v = vec![0x20]; // even leaf prefix
            v.extend_from_slice(&[0u8; 32]); // 64 zero nibbles
            v
        };
        let value = vec![0x12, 0x34];

        // RLP encode: [compact_key, value]
        let encoded_key = rlp_encode_bytes(&compact_key);
        let encoded_value = rlp_encode_bytes(&value);
        let list_payload = [encoded_key.as_slice(), encoded_value.as_slice()].concat();
        let leaf_rlp = rlp_encode_list(&list_payload);

        let root: [u8; 32] = keccak256(&leaf_rlp).0;

        let result = verify_mpt_proof(root, &[0u8; 32], &[leaf_rlp]).unwrap();
        assert_eq!(result, vec![0x12, 0x34]);
    }

    #[test]
    fn test_verify_mpt_proof_nonexistent_key() {
        // Build a leaf for key 0x0000...00
        let compact_key = {
            let mut v = vec![0x20];
            v.extend_from_slice(&[0u8; 32]);
            v
        };
        let value = vec![0x12, 0x34];

        let encoded_key = rlp_encode_bytes(&compact_key);
        let encoded_value = rlp_encode_bytes(&value);
        let list_payload = [encoded_key.as_slice(), encoded_value.as_slice()].concat();
        let leaf_rlp = rlp_encode_list(&list_payload);

        let root: [u8; 32] = keccak256(&leaf_rlp).0;

        // Search for a different key -- should return empty (not found)
        let result = verify_mpt_proof(root, &[0xffu8; 32], &[leaf_rlp]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_proof_returns_empty() {
        let result = verify_mpt_proof(EMPTY_TRIE_ROOT, &[0u8; 32], &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_proof_rejected_for_non_empty_root() {
        // Any non-empty root should require at least one proof node.
        let non_empty_root = keccak256([0x01]).0;
        let err = verify_mpt_proof(non_empty_root, &[0u8; 32], &[]).unwrap_err();
        match err {
            MptError::InvalidProof(_) => {}
            other => panic!("expected InvalidProof, got {other:?}"),
        }
    }

    #[test]
    fn test_storage_proof_empty_trie() {
        // Empty storage trie root should return zero for any slot
        let empty_root: [u8; 32] = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ];
        let slot = [0u8; 32];
        let result = verify_storage_proof(empty_root, &slot, &[]).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_verify_account_proof_single_leaf() {
        // Build a single-leaf state trie with one account.
        // The key is keccak256(address), the value is RLP([nonce, balance, storageRoot, codeHash]).
        let address: [u8; 20] = [0xaa; 20];
        let key = keccak256(&address);

        let nonce: u64 = 5;
        let balance_bytes = vec![0x01, 0x00]; // 256 wei
        let storage_root = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ]; // empty trie root
        let code_hash = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ]; // keccak256("")

        // Build the RLP-encoded account: [nonce, balance, storageRoot, codeHash]
        let nonce_rlp = rlp_encode_bytes(&[nonce as u8]); // nonce=5
        let balance_rlp = rlp_encode_bytes(&balance_bytes);
        let storage_root_rlp = rlp_encode_bytes(&storage_root);
        let code_hash_rlp = rlp_encode_bytes(&code_hash);

        let account_payload = [
            nonce_rlp.as_slice(),
            balance_rlp.as_slice(),
            storage_root_rlp.as_slice(),
            code_hash_rlp.as_slice(),
        ]
        .concat();
        let account_rlp = rlp_encode_list(&account_payload);

        // Build the leaf node: RLP([compact_key, account_rlp])
        // The key in the trie is keccak256(address) = 32 bytes = 64 nibbles
        // Compact encoding for even leaf: 0x20 + key bytes
        let compact_key = {
            let mut v = vec![0x20]; // even leaf prefix
            v.extend_from_slice(key.as_slice());
            v
        };

        let encoded_key = rlp_encode_bytes(&compact_key);
        // In Ethereum's MPT, leaf values are stored as RLP strings (raw bytes).
        // The account_rlp is an RLP list, but the trie wraps it as a string.
        let encoded_value = rlp_encode_bytes(&account_rlp);
        let leaf_payload = [encoded_key.as_slice(), encoded_value.as_slice()].concat();
        let leaf_rlp = rlp_encode_list(&leaf_payload);

        let root: [u8; 32] = keccak256(&leaf_rlp).0;

        // Now verify
        let result = verify_account_proof(root, &address, &[leaf_rlp]).unwrap();
        let proven = result.expect("account should exist");

        assert_eq!(proven.nonce, 5);
        let mut expected_balance = [0u8; 32];
        expected_balance[30] = 0x01;
        expected_balance[31] = 0x00;
        assert_eq!(proven.balance, expected_balance);
        assert_eq!(proven.storage_root, storage_root);
        assert_eq!(proven.code_hash, code_hash);
    }

    #[test]
    fn test_verify_storage_proof_single_leaf() {
        // Build a single-leaf storage trie with one slot.
        let slot: [u8; 32] = [0u8; 32]; // slot 0
        let key = keccak256(&slot);

        // The storage value: 42 (0x2a)
        let value_bytes = vec![0x2a];
        let value_rlp = rlp_encode_bytes(&value_bytes);

        // Build leaf: RLP([compact_key, value_rlp])
        let compact_key = {
            let mut v = vec![0x20]; // even leaf prefix
            v.extend_from_slice(key.as_slice());
            v
        };

        let encoded_key = rlp_encode_bytes(&compact_key);
        // In Ethereum's MPT, leaf values are stored as RLP strings.
        let encoded_value = rlp_encode_bytes(&value_rlp);
        let leaf_payload = [encoded_key.as_slice(), encoded_value.as_slice()].concat();
        let leaf_rlp = rlp_encode_list(&leaf_payload);

        let storage_root: [u8; 32] = keccak256(&leaf_rlp).0;

        let result = verify_storage_proof(storage_root, &slot, &[leaf_rlp]).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 0x2a;
        assert_eq!(result, expected);
    }

    // --- Helper functions for building test RLP ---

    fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        if data.len() <= 55 {
            let mut out = vec![0x80 + data.len() as u8];
            out.extend_from_slice(data);
            out
        } else {
            let len_bytes = encode_length(data.len());
            let mut out = vec![0xb7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(data);
            out
        }
    }

    fn rlp_encode_list(payload: &[u8]) -> Vec<u8> {
        if payload.len() <= 55 {
            let mut out = vec![0xc0 + payload.len() as u8];
            out.extend_from_slice(payload);
            out
        } else {
            let len_bytes = encode_length(payload.len());
            let mut out = vec![0xf7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(payload);
            out
        }
    }

    fn encode_length(len: usize) -> Vec<u8> {
        if len <= 0xff {
            vec![len as u8]
        } else if len <= 0xffff {
            vec![(len >> 8) as u8, len as u8]
        } else {
            vec![(len >> 16) as u8, (len >> 8) as u8, len as u8]
        }
    }

    #[test]
    fn test_verify_mpt_proof_inline_node() {
        // Construct a trie: Root -> Branch -> Leaf
        // Key: 0x00...00 (nibbles 0, 0, ...)
        // We want the Leaf to be small enough to be inlined in the Branch.
        // Leaf value: 0x42
        // Leaf RLP: RLP([compact_key, value])
        // If we make the leaf part of the path short, it might work.
        // Let's say we have traversed some nibbles and are at the Branch.
        // The Branch has a child at index 0.
        // That child is a Leaf.

        // Construct the Leaf first.
        // Let's assume the key suffix at this point is just one nibble '0'.
        // Even leaf with 1 nibble? No, compact encoding is bytes.
        // 1 nibble '0' -> odd leaf, prefix 0x30.
        let compact_key = vec![0x30];
        let value = vec![0x42];

        let encoded_key = rlp_encode_bytes(&compact_key);
        let encoded_value = rlp_encode_bytes(&value);
        let leaf_payload = [encoded_key.as_slice(), encoded_value.as_slice()].concat();
        let leaf_rlp = rlp_encode_list(&leaf_payload);

        // leaf_rlp length:
        // encoded_key: 1 byte (0x30) -> rlp 0x30 (since < 0x80)
        // encoded_value: 1 byte (0x42) -> rlp 0x42
        // payload: 2 bytes
        // list: 0xc2, 0x30, 0x42. Length = 3 bytes.
        // This is definitely < 32 bytes, so it should be inlined in the parent branch.
        assert!(leaf_rlp.len() < 32);

        // Construct the Branch.
        // Children 0..15, plus value.
        // Child 0 is the leaf_rlp (inline).
        // Others empty.
        let mut branch_payload = Vec::new();
        // Child 0
        branch_payload.extend_from_slice(&rlp_encode_bytes(&leaf_rlp));
        // Children 1..15 (empty strings -> 0x80)
        for _ in 1..16 {
            branch_payload.push(0x80);
        }
        // Value (empty -> 0x80)
        branch_payload.push(0x80);

        let branch_rlp = rlp_encode_list(&branch_payload);

        // The root points to the branch.
        let root = keccak256(&branch_rlp).0;

        // The proof provided by the prover contains the nodes in path order.
        // 1. Branch node
        // 2. Leaf node? NO.
        // If the node is inline, it is NOT provided as a separate proof node hash-lookup.
        // It is embedded in the parent.
        // HOWEVER, our `verify_mpt_proof` iterates over `proof_nodes`.
        // Does EIP-1186 / getProof include inline nodes as separate items in the proof list?
        // Yes, typically `eth_getProof` returns the full path of nodes.
        // Even if it's inline, the client needs to "traverse" it.
        // Let's verify our logic:
        // logic says: "If expected_ptr.len() < 32, verify node_rlp == expected_ptr".
        // expected_ptr comes from `items[child_idx]`.
        // `items[child_idx]` for Child 0 will be the raw `leaf_rlp` bytes (since we encoded it as bytes in the list).
        // Wait, `rlp_encode_list` wraps items.
        // Inside the branch RLP, the child 0 is `0x83 0xc2 0x30 0x42` (string encoding of the list)?
        // No, in MPT, if a child is inline, it is just the list itself `0xc2 0x30 0x42`.
        // But `rlp_decode_list` expects the items to be RLP encoded.
        // If the child is `[0xc2, 0x30, 0x42]`, that IS an RLP list.
        // So `items[child_idx]` will be `[0xc2, 0x30, 0x42]`.
        // So `expected_ptr` becomes `[0xc2, 0x30, 0x42]`.
        // Then the next `proof_node` (node_rlp) MUST be `[0xc2, 0x30, 0x42]`.
        // And `node_rlp == expected_ptr` check will pass.

        // So we need to provide [branch_rlp, leaf_rlp] as the proof.

        let proof = vec![branch_rlp, leaf_rlp];
        // Key: 1 byte 0x00 -> nibbles 0, 0.
        // Branch consumes nibble 0. Leaf consumes nibble 0. Total 2 nibbles.
        let key = [0u8; 1];

        let result = verify_mpt_proof(root, &key, &proof).unwrap();
        assert_eq!(result, value);
    }
}
