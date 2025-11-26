use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};


pub mod setup;
pub mod prove;
pub mod verify;

pub const LEAVES_POSEIDON_DOMAIN: u64 = 1;

#[derive(Clone)]
pub struct PoseidonMerkleHasher;

pub struct ProofInput<'a> {
    pub secret: &'a Fr,
    pub witness: &'a Fr,
    pub blinding: &'a Fr,
    pub generator_g: &'a G1Affine,
    pub generator_h: &'a G1Affine,
    pub generator_b: &'a G1Affine,
    pub anchor: &'a G1Affine,
    pub tree: &'a MerkleTree<PoseidonMerkleHasher>,
}

pub struct AnchoredProof {
    pub commitment: G1Affine,
    pub modified_commitment: G1Affine,
    pub p_point: G1Affine,  // The point P = G*(secret*witness) used in leaf computation
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

pub fn split_fq_to_fr<Fq, Fr>(fq_elem: &Fq) -> Vec<Fr>
where
    Fq: PrimeField,
    Fr: PrimeField,
{
    let fq_bigint = fq_elem.into_bigint();
    let bytes = fq_bigint.to_bytes_le();

    let (low_bytes, high_bytes) = bytes.split_at(16);
    let low_fr = Fr::from_le_bytes_mod_order(low_bytes);
    let high_fr = Fr::from_le_bytes_mod_order(high_bytes);

    vec![low_fr, high_fr]
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
    use ark_bn254::{Fq, Fr};
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};
    use super::*;
    use crate::{setup::*, prove::generate_anchored_proof, ProofInput};

    #[test]
    fn test_end_to_end_proof_generation() {
        // ------------------------------------------------------------------
        // 1. SETUP PHASE
        // ------------------------------------------------------------------
        println!("Step 1: Generators and Secrets Setup");
        
        let (g, h, b) = generator_setup();
        
        let secret = secret_setup();
        
        let blinding = secret_setup();

        let anchor = anchor_setup(&secret, &b);

        // ------------------------------------------------------------------
        // 2. TREE CONSTRUCTION
        // ------------------------------------------------------------------
        println!("Step 2: Merkle Tree Construction");
        
        let range = 8; 
        let tree = tree_setup(range, &anchor, &secret);

        // ------------------------------------------------------------------
        // 3. WITNESS SELECTION
        // ------------------------------------------------------------------
        println!("Step 3: Witness Selection");

        let witness_value = 2u64;
        let witness = Fr::from(witness_value);

        // ------------------------------------------------------------------
        // 4. PROOF GENERATION
        // ------------------------------------------------------------------
        println!("Step 4: Proof Generation");

        let input = ProofInput {
            secret: &secret,
            witness: &witness,
            blinding: &blinding,
            generator_g: &g,
            generator_h: &h,
            generator_b: &b,
            anchor: &anchor,
            tree: &tree,
        };

        let proof = generate_anchored_proof(input);

        // ------------------------------------------------------------------
        // 5. ASSERTIONS & VALIDATION
        // ------------------------------------------------------------------
        println!("Step 5: Validation");

        let witness_index = (witness_value - 1) as usize;

        let valid_root = proof.merkle_proof.verify(
            tree.root().unwrap(),                 
            &[witness_index],                    
            &[proof.leaf_hash],                  
            tree.leaves_len()                    
        );

    assert!(valid_root, "Merkle Proof verification failed");
    println!("Merkle Proof Verified: true");

    assert!(!proof.dleq_proof.r_commitment_1.is_zero(), "DLEQ R1 should not be zero");
    assert!(!proof.dleq_proof.r_commitment_2.is_zero(), "DLEQ R2 should not be zero");

    assert!(!proof.schnorr_proof.commitment.is_zero(), "Schnorr commitment should not be zero");

    println!("Test Passed: Full flow completed successfully.");
    }

    #[test]
    #[ignore]
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
    #[ignore]
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
    #[ignore]
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