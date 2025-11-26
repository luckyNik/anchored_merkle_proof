use ark_ff::{BigInteger, BigInteger256, PrimeField, UniformRand};
use light_poseidon::{Poseidon, PoseidonHasher};
use rs_merkle::MerkleTree;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, short_weierstrass::Affine};
use ark_std::test_rng;
use ark_bn254::{Fr, G1Affine, G1Projective, g1};
use sha2::{Digest, Sha256};
use crate::{LEAVES_POSEIDON_DOMAIN, PoseidonMerkleHasher, split_fq_to_fr};

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

pub fn anchor_setup (secret: &Fr, generator: &G1Affine) -> G1Affine {
    ((*generator)*(*secret)).into_affine()
}

pub fn tree_setup(range: u8, anchor: &G1Affine, a: &Fr) -> MerkleTree<PoseidonMerkleHasher> {
    let anchor_x_limbs = split_fq_to_fr(&anchor.x().unwrap());

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
            Fr::from(LEAVES_POSEIDON_DOMAIN), 
            anchor_x_limbs[0], anchor_x_limbs[1], p_x_limbs[0], p_x_limbs[1]]).unwrap();

        let mut bytes = [0u8; 32];
        let v = hash.into_bigint().to_bytes_be();
        bytes[32 - v.len()..].copy_from_slice(&v);
        leaves.push(bytes);
        x.add_with_carry(&BigInteger256::one());
    }
    MerkleTree::<PoseidonMerkleHasher>::from_leaves(&leaves)
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