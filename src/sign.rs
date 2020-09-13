use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::ThreadRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use types::*;

/// preprocess is performed by each participant; their commitments are published
/// and stored in an external location for later use in signing, while their
/// signing nonces are stored locally.
pub fn preprocess(
    number_commitments: usize,
    participant_index: u32,
    participant_pubkey: RistrettoPoint,
    rng: &mut ThreadRng,
) -> Result<(Vec<SigningCommitment>, Vec<NoncePair>), &'static str> {
    let mut nonces: Vec<NoncePair> = Vec::with_capacity(number_commitments);
    let mut commitments = Vec::with_capacity(number_commitments);

    for _ in 0..number_commitments {
        let nonce_pair = NoncePair::new(rng)?;
        nonces.push(nonce_pair);

        let commitment = SigningCommitment::new(
            nonce_pair.d.public,
            nonce_pair.e.public,
            participant_index,
            participant_pubkey,
        )?;

        commitments.push(commitment);
    }

    Ok((commitments, nonces))
}

/// sign is performed by each participant selected for the signing
/// operation; these responses are then aggregated into the final FROST
/// signature by the signature aggregator performing the aggregate function
/// with each response.
pub fn sign(
    keypair: &KeyPair,
    signing_commitments: &Vec<SigningCommitment>,
    signing_nonces: &mut Vec<NoncePair>,
    msg: &str,
) -> Result<SigningResponse, &'static str> {
    let mut bindings: HashMap<u32, Scalar> = HashMap::with_capacity(signing_commitments.len());

    for counter in 0..signing_commitments.len() {
        let comm = signing_commitments[counter];
        let rho_i = gen_rho_i(comm.index, msg, signing_commitments);
        bindings.insert(comm.index, rho_i);
    }

    let group_commitment = gen_group_commitment(&signing_commitments, &bindings)?;

    let indices = signing_commitments.iter().map(|item| item.index).collect();

    let lambda_i = get_lagrange_coeff(keypair.index, &indices)?;

    // find the corresponding nonces for this participant
    let my_comm = match signing_commitments
        .iter()
        .find(|item| item.index == keypair.index)
    {
        Some(v) => v,
        None => return Err("No signing commitment for signer"),
    };

    let signing_nonce = match signing_nonces
        .iter_mut()
        .find(|item| item.d.public == my_comm.d && item.e.public == my_comm.e)
    {
        Some(v) => v,
        None => return Err("No matching signing nonce for signer"),
    };

    // now mark the nonce as having been used, return an error if it is already used
    match signing_nonce.dirty {
        false => signing_nonce.mark_as_used(),
        true => return Err("signing nonce has already been used!"),
    }

    let my_rho_i = bindings[&keypair.index];

    let c = gen_c(msg, group_commitment);

    let response = signing_nonce.d.secret
        + (signing_nonce.e.secret * my_rho_i)
        + (lambda_i * keypair.secret * c);

    Ok(SigningResponse {
        response: response,
        index: keypair.index,
    })
}

/// aggregate collects all responses from participants. It first performs a
/// validity check for each participant's response, and will return an error in the
/// case the response is invalid. If all responses are valid, it aggregates these
/// into a single signature that is published. This function is executed
/// by the entity performing the signature aggregator role.
pub fn aggregate(
    msg: &str,
    signing_commitments: &Vec<SigningCommitment>,
    signing_responses: &Vec<SigningResponse>,
) -> Result<Signature, &'static str> {
    // first, make sure that each commitment corresponds to exactly one response
    let mut commitment_indices = signing_commitments
        .iter()
        .map(|com| com.index)
        .collect::<Vec<u32>>();
    let mut response_indices = signing_responses
        .iter()
        .map(|com| com.index)
        .collect::<Vec<u32>>();

    commitment_indices.sort();
    response_indices.sort();

    if commitment_indices.len() != response_indices.len() {
        return Err("Mismatched number of commitments and responses");
    }
    for counter in 0..commitment_indices.len() {
        if commitment_indices[counter] != response_indices[counter] {
            return Err("Mismatched commitment without corresponding response");
        }
    }

    let mut bindings: HashMap<u32, Scalar> = HashMap::with_capacity(signing_commitments.len());

    for counter in 0..signing_commitments.len() {
        let comm = signing_commitments[counter];
        let rho_i = gen_rho_i(comm.index, msg, signing_commitments);
        bindings.insert(comm.index, rho_i);
    }

    let group_commitment = gen_group_commitment(&signing_commitments, &bindings)?;
    let c = gen_c(msg, group_commitment);

    // check the validity of each participant's response
    for resp in signing_responses {
        let matching_rho_i = bindings[&resp.index];

        let indices = signing_commitments.iter().map(|item| item.index).collect();

        let lambda_i = get_lagrange_coeff(resp.index, &indices)?;

        let matching_commitment = match signing_commitments.iter().find(|x| x.index == resp.index) {
            Some(x) => x,
            None => return Err("No matching commitment for response"),
        };

        let comm_i = matching_commitment.d + (matching_commitment.e * matching_rho_i);
        let is_valid = (&constants::RISTRETTO_BASEPOINT_TABLE * &resp.response)
            == (comm_i + (matching_commitment.signer_pubkey * (c * lambda_i)));

        if !is_valid {
            return Err("Invalid signer response");
        }
    }

    let group_resp = signing_responses
        .iter()
        .fold(Scalar::zero(), |acc, x| acc + x.response);

    Ok(Signature {
        r: group_commitment,
        z: group_resp,
    })
}

/// validate instantiates a plain Schnorr validation operation
pub fn validate(msg: &str, sig: &Signature, pubkey: RistrettoPoint) -> Result<(), &'static str> {
    let c = gen_c(msg, sig.r);

    match sig.r == (&constants::RISTRETTO_BASEPOINT_TABLE * &sig.z) - (pubkey * c) {
        true => Ok(()),
        false => Err("Signature is invalid"),
    }
}

pub fn gen_c(msg: &str, group_commitment: RistrettoPoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.update(group_commitment.compress().to_bytes());
    let result = hasher.finalize();
    Scalar::from_bytes_mod_order(slice_to_array_helper(result.as_slice()))
}

fn get_lagrange_coeff(
    signer_index: u32,
    all_signer_indices: &Vec<u32>,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in all_signer_indices {
        if *j == signer_index {
            continue;
        }
        num *= Scalar::from(*j);
        den *= Scalar::from(*j) - Scalar::from(signer_index);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

fn slice_to_array_helper(s: &[u8]) -> [u8; 32] {
    s.try_into().expect("slice with incorrect length")
}

fn gen_rho_i(index: u32, msg: &str, signing_commitments: &Vec<SigningCommitment>) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update("I".as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(msg.as_bytes());
    for item in signing_commitments {
        hasher.update(item.index.to_be_bytes());
        hasher.update(item.d.compress().as_bytes());
        hasher.update(item.e.compress().as_bytes());
    }
    let result = hasher.finalize();

    Scalar::from_bytes_mod_order(slice_to_array_helper(result.as_slice()))
}

fn gen_group_commitment(
    signing_commitments: &Vec<SigningCommitment>,
    bindings: &HashMap<u32, Scalar>,
) -> Result<RistrettoPoint, &'static str> {
    let mut accumulator = RistrettoPoint::identity();

    for commitment in signing_commitments {
        let rho_i = bindings[&commitment.index];

        accumulator += commitment.d + (commitment.e * rho_i)
    }

    Ok(accumulator)
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
        let (signing_commitments, signing_nonces) =
            preprocess(5, 1, RistrettoPoint::identity(), &mut rng).unwrap();
        assert!(signing_commitments.len() == 5);
        assert!(signing_nonces.len() == 5);

        let expected_length = signing_nonces.len() * 2;
        let mut seen_nonces = Vec::with_capacity(expected_length);
        for nonce in signing_nonces {
            seen_nonces.push(nonce.d.secret);
            seen_nonces.push(nonce.e.secret);
        }
        seen_nonces.dedup();

        // ensure that each secret is unique
        assert!(seen_nonces.len() == expected_length);
    }

    fn gen_signing_helper(
        threshold: u32,
        keypairs: &Vec<KeyPair>,
        rng: &mut ThreadRng,
    ) -> (Vec<SigningCommitment>, HashMap<u32, Vec<NoncePair>>) {
        let mut nonces: HashMap<u32, Vec<NoncePair>> = HashMap::with_capacity(threshold as usize);
        let mut signing_commitments: Vec<SigningCommitment> =
            Vec::with_capacity(threshold as usize);
        let number_nonces_to_generate = 1;

        for counter in 0..threshold {
            let signing_keypair = &keypairs[counter as usize];
            let (participant_commitments, participant_nonces) = preprocess(
                number_nonces_to_generate,
                signing_keypair.index,
                signing_keypair.public,
                rng,
            )
            .unwrap();

            signing_commitments.push(participant_commitments[0]);
            nonces.insert(counter, participant_nonces);
        }
        assert!(nonces.len() == (threshold as usize));
        (signing_commitments, nonces)
    }

    fn gen_keypairs_dkg_helper(num_shares: u32, threshold: u32) -> Vec<KeyPair> {
        let mut rng: ThreadRng = rand::thread_rng();

        let mut participant_shares: HashMap<u32, Vec<Share>> =
            HashMap::with_capacity(num_shares as usize);
        let mut participant_commitments: Vec<KeyGenDKGProposedCommitment> =
            Vec::with_capacity(num_shares as usize);
        let mut participant_keypairs: Vec<KeyPair> = Vec::with_capacity(num_shares as usize);

        for counter in 0..num_shares {
            let participant_index = counter + 1;
            let (com, shares) =
                keygen_begin(num_shares, threshold, participant_index, &mut rng).unwrap();

            for share in shares {
                match participant_shares.get_mut(&share.receiver_index) {
                    Some(list) => list.push(share),
                    None => {
                        let mut list = Vec::with_capacity(num_shares as usize);
                        list.push(share);
                        participant_shares.insert(share.receiver_index, list);
                    }
                }
            }
            participant_commitments.push(com);
        }

        let (invalid_peer_ids, valid_commitments) =
            keygen_receive_commitments_and_validate_peers(participant_commitments);
        assert!(invalid_peer_ids.len() == 0);

        // now, finalize the protocol
        for counter in 0..num_shares {
            let participant_index = counter + 1;
            let res = match keygen_finalize(
                participant_index, // participant indices should start at 1
                &participant_shares[&participant_index],
                &valid_commitments,
            ) {
                Ok(x) => x,
                Err(err) => panic!(err),
            };

            participant_keypairs.push(res);
        }

        participant_keypairs
    }

    #[test]
    fn valid_sign_with_single_dealer() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, keypairs) = keygen_with_dealer(num_signers, threshold, &mut rng).unwrap();

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let group_sig = aggregate(msg, &signing_package, &all_responses).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    #[test]
    fn valid_sign_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let group_sig = aggregate(msg, &signing_package, &all_responses).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    #[test]
    fn valid_sign_with_dkg_larger_params() {
        let num_signers = 10;
        let threshold = 6;
        let mut rng: ThreadRng = rand::thread_rng();

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing larger params sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let group_sig = aggregate(msg, &signing_package, &all_responses).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    #[test]
    fn invalid_sign_too_few_responses_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..(threshold - 1) {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        // duplicate a share
        all_responses.push(all_responses[0]);

        let res = aggregate(msg, &signing_package, &all_responses);
        assert!(!res.is_ok());
    }

    #[test]
    fn invalid_sign_invalid_response_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        // create a totally invalid response
        all_responses[0].response = Scalar::from(42u32);

        let res = aggregate(msg, &signing_package, &all_responses);
        assert!(!res.is_ok());
    }

    #[test]
    fn invalid_sign_bad_group_public_key_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing different message sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let group_sig = aggregate(msg, &signing_package, &all_responses).unwrap();
        // use one of the participant's public keys instead
        let invalid_group_pubkey = keypairs[0 as usize].public;
        assert!(!validate(msg, &group_sig, invalid_group_pubkey).is_ok());
    }

    #[test]
    fn invalid_sign_dirty_nonce_with_dkg() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let keypairs = gen_keypairs_dkg_helper(num_signers, threshold);

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut my_signing_nonces = signing_nonces[&0].clone();

        // set the signing nonce for the first signer to already having been used
        my_signing_nonces[0].mark_as_used();

        let res = sign(&keypairs[0], &signing_package, &mut my_signing_nonces, msg);

        assert!(!res.is_ok());
    }

    #[test]
    fn invalid_sign_with_dealer() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, keypairs) = keygen_with_dealer(num_signers, threshold, &mut rng).unwrap();

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        {
            // test duplicated participants
            for counter in 0..threshold {
                let mut my_signing_nonces = signing_nonces[&counter].clone();
                assert!(my_signing_nonces.len() == 1);
                let res = sign(
                    &keypairs[counter as usize],
                    &signing_package,
                    &mut my_signing_nonces,
                    msg,
                )
                .unwrap();

                all_responses.push(res);
            }

            let group_sig = aggregate(msg, &signing_package, &all_responses).unwrap();
            let invalid_group_pubkey = RistrettoPoint::identity();
            assert!(!validate(msg, &group_sig, invalid_group_pubkey).is_ok());
        }
    }

    #[test]
    fn valid_validate_single_party() {
        let privkey = Scalar::from(42u32);
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
        assert!(validate(msg, &sig, pubkey).is_ok());
    }

    #[test]
    fn invalid_validate_single_party() {
        let privkey = Scalar::from(42u32);
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
        assert!(!validate(msg, &sig, pubkey).is_ok());
    }
}
