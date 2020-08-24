use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::ThreadRng;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use types::*;

pub fn get_lagrange_coeff(
    signer_index: u32,
    all_signer_indices: &Vec<u32>,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in all_signer_indices.clone() {
        if j == signer_index {
            continue;
        }
        num *= Scalar::from(j as u32);
        den *= Scalar::from(j) - Scalar::from(signer_index);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

/// preprocess is performed by all participants; their commitments are published
/// and stored in an external location for later use in signing, while their
/// signing nonces are stored locally.
pub fn preprocess(
    number_commitments: usize,
    rng: &mut ThreadRng,
) -> (Vec<SigningCommitment>, Vec<Nonce>) {
    let mut nonces: Vec<Nonce> = Vec::with_capacity(number_commitments);

    for _ in 0..number_commitments {
        let d = Scalar::random(rng);
        let e = Scalar::random(rng);

        nonces.push(Nonce {
            d: NonceInstance {
                secret: d,
                public: &constants::RISTRETTO_BASEPOINT_TABLE * &d,
            },
            e: NonceInstance {
                secret: e,
                public: &constants::RISTRETTO_BASEPOINT_TABLE * &e,
            },
            is_dirty: false,
        });
    }

    let commitments: Vec<SigningCommitment> = nonces
        .iter()
        .map(|item| SigningCommitment {
            d_comm: item.d.public,
            e_comm: item.e.public,
        })
        .collect();

    (commitments, nonces)
}

fn slice_to_array_helper(s: &[u8]) -> [u8; 32] {
    s.try_into().expect("slice with incorrect length")
}

fn gen_rho_i(index: usize, msg: &str, signing_package: &SigningPackage) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(index.to_string().as_bytes());
    hasher.update(msg.as_bytes());
    for item in &signing_package.items {
        hasher.update(item.index.to_string().as_bytes());
        hasher.update(item.commitment.d_comm.compress().as_bytes());
        hasher.update(item.commitment.e_comm.compress().as_bytes());
    }
    let result = hasher.finalize();

    Scalar::from_bytes_mod_order(slice_to_array_helper(result.as_slice()))
}

fn gen_group_commitment(msg: &str, signing_package: &SigningPackage) -> RistrettoPoint {
    signing_package
        .items
        .iter()
        .map(|item| {
            item.commitment.d_comm
                + (item.commitment.e_comm) * gen_rho_i(item.index, msg, signing_package)
        })
        .fold(RistrettoPoint::identity(), |acc, x| acc + x)
}

fn gen_c(msg: &str, group_commitment: RistrettoPoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.update(group_commitment.compress().to_bytes());
    let result = hasher.finalize();
    Scalar::from_bytes_mod_order(slice_to_array_helper(result.as_slice()))
}

/// sign is performed by all participants selected for the signing operation
pub fn sign(
    keypair: &KeyPair,
    signing_package: &SigningPackage,
    signing_nonces: &mut Vec<Nonce>,
    msg: &str,
) -> Result<SigningResponse, &'static str> {
    println!("starting signing for participant {}", keypair.index);

    let group_commitment = gen_group_commitment(msg, &signing_package);

    let c = gen_c(msg, group_commitment);

    let signing_indices = signing_package
        .items
        .iter()
        .map(|item| item.index as u32)
        .collect();

    let lambda_i = match get_lagrange_coeff(keypair.index as u32, &signing_indices) {
        Ok(v) => v,
        Err(err) => return Err(err),
    };

    // find the corresponding nonces for this participant
    let my_comm = match signing_package
        .items
        .iter()
        .find(|item| item.index == keypair.index)
    {
        Some(v) => v.commitment,
        None => return Err("No signing commitment for signer"),
    };

    let signing_nonce = match signing_nonces
        .iter()
        .find(|item| item.d.public == my_comm.d_comm && item.e.public == my_comm.e_comm)
    {
        Some(v) => v,
        None => return Err("No signing nonce for signer"),
    };

    if signing_nonce.is_dirty {
        return Err("Commitment re-use error; aborting");
    }

    // TODO set the is+dirty bit
    let rho_i = gen_rho_i(keypair.index, msg, signing_package);

    let response =
        signing_nonce.d.secret + (signing_nonce.e.secret * rho_i) + (lambda_i * keypair.secret * c);

    Ok(SigningResponse {
        response: response,
        signer_pubkey: keypair.public,
    })
}

/// aggregate collects all responses from participants and aggregates these
/// into a single signature that is then published; this function is executed
/// by the signature aggregator.
/// TODO add in validation of signatures
pub fn aggregate(
    signing_responses: &Vec<SigningResponse>,
    group_commitment: RistrettoPoint, // TODO validate responses
) -> Result<Signature, &'static str> {
    let resp = signing_responses
        .iter()
        .map(|x| x.response)
        .fold(Scalar::zero(), |acc, x| acc + x);

    Ok(Signature {
        r: group_commitment,
        z: resp,
    })
}

/// validate instantiates a plain Schnorr validation operation
pub fn validate(msg: &str, sig: Signature, pubkey: RistrettoPoint) -> bool {
    let c = gen_c(msg, sig.r);

    sig.r == (&constants::RISTRETTO_BASEPOINT_TABLE * &sig.z) - (pubkey * c)
}

#[cfg(test)]
mod tests {
    use crate::keygen::*;
    use crate::sign::*;
    use rand::rngs::ThreadRng;
    use std::collections::HashMap;

    #[test]
    fn preprocess_generates_values() {
        let mut rng: ThreadRng = rand::thread_rng();
        let (signing_commitments, signing_nonces) = preprocess(5, &mut rng);
        assert!(signing_commitments.len() == 5);
        assert!(signing_nonces.len() == 5);
        //
        // test that the commitments are actually different
        assert!(signing_nonces[0].d.secret != signing_nonces[0].e.secret);
        assert!(signing_nonces[0].d.secret != signing_nonces[1].d.secret);

        // test that the commitments are actually different
        assert!(signing_commitments[0].d_comm != signing_commitments[0].e_comm);
        assert!(signing_commitments[0].d_comm != signing_commitments[1].d_comm);
    }

    fn gen_signing_helper(
        threshold: usize,
        rng: &mut ThreadRng,
    ) -> (SigningPackage, HashMap<u32, Vec<Nonce>>) {
        let mut nonces: HashMap<u32, Vec<Nonce>> = HashMap::with_capacity(threshold);
        let mut signing_package = SigningPackage {
            items: Vec::with_capacity(threshold),
        };

        for index in 1..threshold + 1 {
            println!(
                "generating nonces and commitments for participant {}",
                index
            );
            let (participant_commitments, participant_nonces) = preprocess(1, rng);

            signing_package.items.push(SigningItem {
                index: index,
                commitment: participant_commitments[0],
            });
            nonces.insert(index as u32, participant_nonces);
        }
        assert!(signing_package.items.len() == threshold);
        assert!(nonces.len() == threshold);
        (signing_package, nonces)
    }

    #[test]
    fn valid_sign() {
        let num_signers: usize = 5;
        let threshold: usize = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let keygen_res = keygen_with_dealer(num_signers, threshold, &mut rng);
        assert!(keygen_res.is_ok());
        let (_, keypairs, group_pub_key) = keygen_res.unwrap();

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold);
        let group_commitment = gen_group_commitment(msg, &signing_package);

        for index in 1..threshold + 1 {
            println!("generating signature for participant {}", index);
            let mut my_signing_nonces = signing_nonces[&(index as u32)].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[&(index as u32)],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();
            println!("finished signing for participant {}", index);

            all_responses.push(res);
        }

        let group_sig = aggregate(&all_responses, group_commitment).unwrap();
        let is_valid = validate(msg, group_sig, group_pub_key);
        assert!(is_valid);
    }

    #[test]
    fn valid_validate_single_party() {
        let privkey = Secret::from(42u32);
        let pubkey = &constants::RISTRETTO_BASEPOINT_TABLE * &privkey;

        let msg = "testing sign";
        let nonce = Scalar::from(5u32); // random nonce
        let commitment = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let c = gen_c(msg, commitment);

        let z = nonce + privkey * c;

        let sig = Signature {
            r: commitment,
            z: z,
        };
        let is_valid = validate(msg, sig, pubkey);
        assert!(is_valid);
    }

    #[test]
    fn invalid_validate_single_party() {
        let privkey = Secret::from(42u32);
        let pubkey = &constants::RISTRETTO_BASEPOINT_TABLE * &privkey;

        let msg = "testing sign";
        let nonce = Scalar::from(5u32); // random nonce
        let commitment = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let c = gen_c(msg, commitment);

        let invalid_nonce = Scalar::from(100u32); // random nonce
        let z = invalid_nonce + privkey * c;

        let sig = Signature {
            r: commitment,
            z: z,
        };
        let is_valid = validate(msg, sig, pubkey);
        assert!(!is_valid);
    }

    #[test]
    fn valid_preprocess_can_sign_valid_simple_schnorr() {
        let mut rng: ThreadRng = rand::thread_rng();
        let (_, keypairs, group_pubkey) = keygen_with_dealer(3, 1, &mut rng).unwrap();
        let signer_one = keypairs[&1];

        let msg = "testing sign";
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, signing_nonces) = preprocess(1, &mut rng);
        let min_signers = vec![1];
        let lambda_1 = get_lagrange_coeff(1, &min_signers).unwrap();
        {
            let nonce = signing_nonces[0].d.secret; // random nonce
            let commitment = signing_nonces[0].d.public;
            let c = gen_c(msg, commitment);

            let z = nonce + (signer_one.secret * lambda_1 * c);

            let sig = Signature {
                r: commitment,
                z: z,
            };
            let is_valid = validate(msg, sig, group_pubkey);
            assert!(is_valid);
        }
        {
            let nonce = signing_nonces[0].e.secret; // random nonce
            let commitment = signing_nonces[0].e.public;
            let c = gen_c(msg, commitment);

            let z = nonce + (signer_one.secret * lambda_1 * c);

            let sig = Signature {
                r: commitment,
                z: z,
            };
            let is_valid = validate(msg, sig, group_pubkey);
            assert!(is_valid);
        }
    }
}
