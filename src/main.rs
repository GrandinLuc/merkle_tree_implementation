#![allow(dead_code)]
#![allow(unused_variables)]
extern crate hex;
extern crate openssl;

use sha2::Digest;

pub type Data<'a> = Vec<u8>;
pub type Hash = Vec<u8>;

pub struct MerkleTree {
    root_hash: Hash,
    tree: Vec<Vec<Hash>>,
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl<'a> MerkleTree {
    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let data_unhashed = input;

        let mut hashed_data: Vec<Hash> = vec![];
        for element in data_unhashed {
            hashed_data.push(hash_data(element));
        }

        let tree: Vec<Vec<Hash>> = recursive_merkle_tree(vec![hashed_data]);

        MerkleTree {
            root_hash: tree.last().unwrap().last().unwrap().to_vec(),
            tree: tree,
        }
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        let tree = MerkleTree::construct(input);

        &tree.root_hash == root_hash
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

fn recursive_merkle_tree(hashed_data: Vec<Vec<Hash>>) -> Vec<Vec<Hash>> {
    let mut res: Vec<Vec<Hash>> = hashed_data;

    if res.last().unwrap().len() > 1 {
        let mut level_hashes: Vec<Hash> = Vec::new();

        for i in 0..res.last().unwrap().len() / 2 {
            level_hashes.push(hash_concat(
                &res.last().unwrap()[i],
                &res.last().unwrap()[i + 1],
            ))
        }

        res.push(level_hashes);

        recursive_merkle_tree(res)
    } else {
        res
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    use crate::Data;
    use crate::MerkleTree;

    #[test]
    fn construct_correct() {
        let data: Vec<Data> = vec![
            vec![0, 1, 3, 200, 200, 201, 230],
            vec![0, 1, 4, 200, 200, 201, 230],
            vec![0, 1, 42, 230, 200, 201, 230],
            vec![0, 1, 25, 200, 200, 201, 230],
        ];

        let merkle_tree = MerkleTree::construct(&data);
        assert!(merkle_tree.root_hash.len() == 32);

        assert!(merkle_tree.tree.len() == 3);
        assert!(merkle_tree.tree.first().unwrap().len() == 4);
    }

    #[test]
    fn verify_correct() {
        let data: Vec<Data> = vec![
            vec![0, 1, 3, 200, 200, 201, 230],
            vec![0, 1, 4, 200, 200, 201, 230],
            vec![0, 1, 42, 230, 200, 201, 230],
            vec![0, 1, 25, 200, 200, 201, 230],
        ];
        let root = vec![
            201, 225, 191, 7, 28, 171, 200, 102, 218, 182, 217, 57, 83, 52, 237, 142, 146, 42, 18,
            112, 50, 187, 70, 252, 143, 61, 167, 209, 37, 23, 160, 84,
        ];
        assert!(MerkleTree::verify(&data, &root))
    }
}
