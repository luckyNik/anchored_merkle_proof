use ark_bn254::{Fr, G1Affine, G1Projective, g1};
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::Affine};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::test_rng;
use light_poseidon::{Poseidon, PoseidonHasher};
use rs_merkle::MerkleProof;

use crate::{AnchoredProof, DLEQProof, LEAVES_POSEIDON_DOMAIN, PoseidonMerkleHasher, ProofInput, SchnorrProof, split_fq_to_fr};

pub fn generate_anchored_proof(input: ProofInput) -> AnchoredProof {
    // 1. Reconstruct Commitments
    let commitment = (*input.generator_g) * input.witness + (*input.generator_h) * input.blinding;
    let modified_commitment = commitment.clone() * input.secret;

    // 2. Calculate P (The Anchor link)
    let scalar = input.secret * input.witness;
    let p: Affine<g1::Config> = ((*input.generator_g) * scalar).into();

    // 3. Merkle Leaf Generation
    let anchor_x_limbs = split_fq_to_fr(&input.anchor.x().unwrap());
    let p_x_limbs = split_fq_to_fr(&p.x().unwrap());
    
    let mut poseidon = Poseidon::<Fr>::new_circom(5).unwrap();
    let hash = poseidon.hash(&[
        Fr::from(LEAVES_POSEIDON_DOMAIN),
        anchor_x_limbs[0], anchor_x_limbs[1], 
        p_x_limbs[0], p_x_limbs[1]
    ]).unwrap();

    let mut bytes_hash = [0u8; 32];
    let v = hash.into_bigint().to_bytes_be();
    bytes_hash[32 - v.len()..].copy_from_slice(&v);
    
    // 4. Find Path (Safe Version)
    let mut merkle_path: Option<MerkleProof<PoseidonMerkleHasher>> = None; 
    for leave_index in 0..input.tree.leaves_len() {
        if input.tree.leaves().unwrap()[leave_index] == bytes_hash {
            merkle_path = Some(input.tree.proof(&[leave_index]));
            break;
        }
    }
    
    let merkle_proof = merkle_path.expect("Leaf not found in tree! Inputs do not match any known leaf.");

    let public_blinding = modified_commitment - p;
    
    // 6. Generate Proofs
    
    // DLEQ: Proves Anchor and C' share the same secret 's' relative to bases B and C
    // Note: Ensure input.generator_b is truly the base of input.anchor
    let dleq_proof = generate_dleq_proof(
        &input.secret,
        input.generator_b,          // Base for Anchor
        &commitment.into_affine(),  // Base for Modified Commitment
        input.anchor,               // Anchor
        &modified_commitment.into_affine() // Modified Commitment
    );

    let composite_secret = input.secret * input.blinding;
    
    let schnorr_proof = generate_schnorr_proof(
        &composite_secret,    
        input.generator_h,    
        &public_blinding      
    );

    AnchoredProof { 
        commitment: commitment.into(), 
        modified_commitment: modified_commitment.into(),
        p_point: p.into(),
        leaf_hash: bytes_hash, 
        merkle_proof, 
        dleq_proof, 
        schnorr_proof 
    }
} 

fn generate_schnorr_proof(
    secret: &Fr, 
    generator: &G1Affine,
    public: &G1Projective
) -> SchnorrProof {
    let mut rng = test_rng();

    let r_scalar = Fr::rand(&mut rng);
    
    let r_point = (*generator) * r_scalar;
    let r_affine = r_point.into_affine();
    let public_affine = (*public).into_affine();

    let pk_limbs = split_fq_to_fr(&public_affine.x().unwrap());
    let r_limbs = split_fq_to_fr(&r_affine.x().unwrap());

    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
    let challenge = poseidon.hash(&[
        pk_limbs[0], pk_limbs[1],
        r_limbs[0], r_limbs[1]
    ]).unwrap();

    let response = r_scalar + (challenge * secret);

    SchnorrProof {
        commitment: r_affine,
        response,
    }
}

fn generate_dleq_proof(
    secret: &Fr,
    generator1: &G1Affine, // B
    generator2: &G1Affine, // C
    public1: &G1Affine,    // U
    public2: &G1Affine     // C'
) -> DLEQProof {
    let mut rng = test_rng();

    let r = Fr::rand(&mut rng);

    let r1_affine = (*generator1 * r).into_affine();
    let r2_affine = (*generator2 * r).into_affine();

    let u_limbs = split_fq_to_fr(&public1.x().unwrap());
    let c_modified_limbs = split_fq_to_fr(&public2.x().unwrap());

    let r1_limbs = split_fq_to_fr(&r1_affine.x().unwrap());
    let r2_limbs = split_fq_to_fr(&r2_affine.x().unwrap());

    // Total inputs: 4 points * 2 limbs/point = 8 inputs
    let mut poseidon = Poseidon::<Fr>::new_circom(8).unwrap();

    let challenge = poseidon.hash(&[
        u_limbs[0], u_limbs[1],   // U
        c_modified_limbs[0], c_modified_limbs[1],   // C'
        r1_limbs[0], r1_limbs[1], // R1
        r2_limbs[0], r2_limbs[1]  // R2
    ]).unwrap();

    let response = r + (challenge * secret);

    DLEQProof {
        r_commitment_1: r1_affine,
        r_commitment_2: r2_affine,
        response,
    }
}