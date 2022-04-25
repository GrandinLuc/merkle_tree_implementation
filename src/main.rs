#![allow(dead_code)]
#![allow(unused_variables)]
extern crate hex;
extern crate openssl;

use hex::ToHex;
use openssl::sha;
use sha2::Digest;

pub type Data<'a> = Vec<u8>;
pub type Hash = Vec<u8>;

pub struct MerkleTree {
    root_hash: Hash,
    proofs: Vec<Vec<Hash>>,
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
        let mut data_unhashed = input;

        let mut hashed_data: Vec<Hash> = vec![];
        for element in data_unhashed {
            hashed_data.push(hash_data(element));
        }

        let tree: Vec<Vec<Hash>> = recursive_merkle_tree(vec![hashed_data]);

        MerkleTree {
            root_hash: tree.last().unwrap().last().unwrap().to_vec(),
            proofs: tree,
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
    let mut temp_res: Vec<Vec<Hash>> = hashed_data;

    if temp_res.last().unwrap().len() > 1 {
        let mut res: Vec<Hash> = Vec::new();

        for i in 0..temp_res.last().unwrap().len() / 2 {
            res.push(hash_concat(
                &temp_res.last().unwrap()[i],
                &temp_res.last().unwrap()[i + 1],
            ))
        }
        temp_res.push(res);

        recursive_merkle_tree(temp_res)
    } else {
        temp_res
    }
}

fn main() {

    let data: Data = vec![
        0,1,2,3,4,5,6,7
    ];

    let tree = MerkleTree::construct(&[data]);

    println!(
        "The data's merkle root is: {:?}",
        tree.root_hash
    );

    println!(
        "The whole tree: {:?}",
        tree.proofs
    );

    let data2: Data = vec![
        0,1,2,3,4,5,6,7
    ];
    let root = vec![138, 133, 31, 248, 46, 231, 4, 138, 208, 158, 195, 132, 127, 29, 223, 68, 148, 65, 4, 210, 203, 209, 126, 244, 227, 219, 34, 198, 120, 90, 13, 69];
    println!(
        "Is three correct: {:?}",
        MerkleTree::verify(&[data2], &root )
    );


}

#[cfg(tests)]
mod tests {

    fn test() {}
}
