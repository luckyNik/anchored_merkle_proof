use ark_bn254::{Fr, Fq, G1Affine, G1Projective, g1};
use ark_ff::{BigInt, BigInteger, BigInteger256, PrimeField, UniformRand};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, hashing::{HashToCurve, curve_maps::swu::SWUMap, map_to_curve_hasher::MapToCurveBasedHasher}, mnt6::G1Prepared, short_weierstrass::{Affine, SWCurveConfig}};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher, parameters::bn254_x5};
use std::borrow::Borrow;
use rs_merkle::{Hasher, MerkleTree};
use ark_std::test_rng;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct PoseidonMerkleHasher;

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

fn visualize_tree(tree: &MerkleTree<PoseidonMerkleHasher>) {
    // rs_merkle stores layers as Vec<Vec<[u8; 32]>> ideally, 
    // but usually provides access via generic iterators or layer getters.
    // If strict layer access isn't public, we can infer structure from leaves.

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

// Setup section

pub fn generator_setup () -> (G1Affine, G1Affine, G1Affine){
    let first = G1Affine::generator();
    let second = sample_nums_generator(&[0; 32]);
    let third = sample_nums_generator(&[1; 32]);
    (first, second, third)
}

pub fn secret_setup () -> Fr {
    let mut rng = test_rng();
    Fr::rand(& mut rng)
}

pub fn anchor_setup (secret: Fr, generator: G1Affine) -> G1Affine {
    (generator*secret).into_affine()
}

pub fn tree_setup(range: u8, anchor: &G1Affine, a: &Fr) -> MerkleTree<PoseidonMerkleHasher> {
    let domain_tag = Fr::from(1u64);
    let anchor_x_limbs = split_fq_to_fr(
        &anchor.x().unwrap());

    let mut x = BigInteger256::one();
    let mut count: BigInteger256 = BigInteger256::one();

    count = count << range.into();
    let mut leaves: Vec<[u8; 32]> = Vec::new();

    while x <= count{
        let x_fr = Fr::from(x);
        let scalar = x_fr * a;
        let p: Affine<g1::Config> = (G1Projective::generator() * scalar).into();
        let p_x_limbs = split_fq_to_fr(&p.x().unwrap());
        
        let mut poseidon = Poseidon::<Fr>::new_circom(5).unwrap();
        let hash = poseidon.hash(&[
            domain_tag, 
            anchor_x_limbs[0], anchor_x_limbs[1], p_x_limbs[0], p_x_limbs[1]]).unwrap();

        let mut bytes = [0u8; 32];
        let v = hash.into_bigint().to_bytes_be();
        bytes[32 - v.len()..].copy_from_slice(&v);
        leaves.push(bytes);
        x.add_with_carry(&BigInteger256::one());
    }
    MerkleTree::<PoseidonMerkleHasher>::from_leaves(&leaves)
}


fn split_fq_to_fr<Fq, Fr>(fq_elem: &Fq) -> Vec<Fr>
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

fn sample_nums_generator(seed: &[u8]) -> G1Affine {
    let mut counter = 0u64;
    
    loop {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();

        if let Some(point) = G1Affine::from_random_bytes(&hash) {
            if !point.is_zero() {
                return point;
            }
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct_math() {
        // 1. Create a random point to get a realistic Fq coordinate
        let (_, g1, _) = generator_setup();
        let original_fq = g1.x().unwrap();

        // 2. Split it using your function
        let limbs: Vec<Fr> = split_fq_to_fr(&original_fq);
        let low_part = limbs[0];
        let high_part = limbs[1];

        // 3. Manually Reconstruct: result = low + (high * 2^128)
        // We work in BigInt to cross the boundary between Fr and Fq
        let low_bi = low_part.into_bigint(); 
        let high_bi = high_part.into_bigint();
        
        let mut reconstructed_bytes = vec![];
        let low_bytes = low_bi.to_bytes_le();
        let high_bytes = high_bi.to_bytes_le();
        
        // We only take the valid 16 bytes from our split logic
        reconstructed_bytes.extend_from_slice(&low_bytes[0..16]);
        reconstructed_bytes.extend_from_slice(&high_bytes[0..16]);

        // Pad the rest (if Fq is larger than 32 bytes, usually it's exactly 32 for BN254)
        // BN254 Fq is 254 bits, fitting in 32 bytes.
        
        let reconstructed_fq = Fq::from_le_bytes_mod_order(&reconstructed_bytes);

        println!("Original:      {original_fq}");
        println!("Reconstructed: {reconstructed_fq}");

        assert_eq!(original_fq, reconstructed_fq, "Critical: The split logic corrupted the coordinate!");
    }

    // ------------------------------------------------------------------
    // TEST 2: Tree Generation & Generator Check
    // ------------------------------------------------------------------
    #[test]
    fn test_tree_structure() {
        let range = 4; // Small range for testing (2^4 = 16 leaves)
        let (anchor_base, _, _) = generator_setup();
        let secret = secret_setup();
        let anchor = anchor_setup(secret, anchor_base);
        
        // Run the setup
        let tree = tree_setup(range, &anchor, &secret);

        // 1. Check leaf count
        let expected_leaves = 1 << range;
        assert_eq!(tree.leaves_len(), expected_leaves);

        // 2. Check root exists
        let root = tree.root();
        assert!(root.is_some());
        
        println!("Tree Root (Hex): {}", hex::encode(root.unwrap()));
        
        // Visualize
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