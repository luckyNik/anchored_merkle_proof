use ark_bn254::{Fr, G1Affine, g1};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};


pub mod setup;
pub mod prove;
pub mod verify;

#[derive(Clone)]
pub struct PoseidonMerkleHasher;

pub struct AnchoredProof {
    pub commitment: G1Affine,
    pub modified_commitment: G1Affine,
    pub leaf_hash: [u8; 32],
    pub merkle_proof: MerkleProof<PoseidonMerkleHasher>,
    pub dleq_proof: DLEQProof,
    pub schnorr_proof: SchnorrProof,
}

pub struct DLEQProof {
    pub r_commitment_1: G1Affine,
    pub r_commitment_2: G1Affine,
    pub response: Fr,             
}

pub struct SchnorrProof {
    pub commitment: G1Affine, 
    pub response: Fr,      
}

impl Hasher for PoseidonMerkleHasher {
    type Hash = [u8; 32];
    fn hash(data: &[u8]) -> Self::Hash {
        if data.len() == 64 {
            let (left, right) = data.split_at(32);
            let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
            poseidon.hash_bytes_be(&[left, right]).unwrap()
        } 
        else {
            let mut poseidon = Poseidon::<Fr>::new_circom(1).unwrap();
            poseidon.hash_bytes_be(&[data]).unwrap()
        }
    }
}


#[cfg(test)]
fn visualize_tree(tree: &MerkleTree<PoseidonMerkleHasher>) {

    let leaves = tree.leaves().unwrap();
    let depth = tree.depth();
    
    println!("Root: {:?}", hex::encode(&tree.root().unwrap()[0..4]).to_string() + "...");
    println!("Depth: {}", depth);
    println!("Total Leaves: {}", leaves.len());

    if leaves.len() > 16 {
        println!("(Tree too large to visualize fully, showing first 4 leaves)");
        for (i, leaf) in leaves.iter().take(4).enumerate() {
            println!("Leaf {}: {}...", i, hex::encode(&leaf[0..4]));
        }
        println!("...");
    } else {
        for (i, leaf) in leaves.iter().enumerate() {
            println!("Leaf {}: {}...", i, hex::encode(&leaf[0..4]));
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fq;
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};
    use super::*;
    use crate::setup::*;

    #[test]
    fn test_split_reconstruct_math() {
        let (_, g1, _) = generator_setup();
        let original_fq = g1.x().unwrap();

        let limbs: Vec<Fr> = split_fq_to_fr(&original_fq);
        let low_part = limbs[0];
        let high_part = limbs[1];

        let low_bi = low_part.into_bigint(); 
        let high_bi = high_part.into_bigint();
        
        let mut reconstructed_bytes = vec![];
        let low_bytes = low_bi.to_bytes_le();
        let high_bytes = high_bi.to_bytes_le();
        
        reconstructed_bytes.extend_from_slice(&low_bytes[0..16]);
        reconstructed_bytes.extend_from_slice(&high_bytes[0..16]);
        
        let reconstructed_fq = Fq::from_le_bytes_mod_order(&reconstructed_bytes);

        println!("Original:      {original_fq}");
        println!("Reconstructed: {reconstructed_fq}");

        assert_eq!(original_fq, reconstructed_fq, "Critical: The split logic corrupted the coordinate!");
    }

    #[test]
    fn test_tree_structure() {
        let range = 4; 
        let (anchor_base, _, _) = generator_setup();
        let secret = secret_setup();
        let anchor = anchor_setup(&secret, &anchor_base);
        
        let tree = tree_setup(range, &anchor, &secret);

        let expected_leaves = 1 << range;
        assert_eq!(tree.leaves_len(), expected_leaves);

        let root = tree.root();
        assert!(root.is_some());
        
        println!("Tree Root (Hex): {}", hex::encode(root.unwrap()));
        
        println!("\n--- Visualizing Merkle Tree (Layers) ---");
        visualize_tree(&tree);
    }

    #[test]
    fn distinct_and_not_default() {
        let (g1, g2, g3) = generator_setup();
        println!("{g1:?}");
        println!("{g2:?}");
        println!("{g3:?}");
        assert_ne!(g1, g2);
        assert_ne!(g2, g3);
        assert_ne!(g1, g3);
    }
}