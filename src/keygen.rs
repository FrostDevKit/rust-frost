use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::ThreadRng;
use std::u32;

use sign::{gen_c, validate};
use types::*;

/// keygen_with_dealer generates shares and distributes them via a trusted
/// dealer. Note this approach is not the FROST specified key generation
/// protocol but we include this to demonstrate its compatibility with the
/// FROST signing protocol.
pub fn keygen_with_dealer(
    numshares: u32,
    threshold: u32,
    rng: &mut ThreadRng,
) -> Result<(SharesCommitment, Vec<KeyPair>), &'static str> {
    let secret = Scalar::random(rng);
    // set generator_index to 0 as we are generating shares with a dealer
    let (shares_com, shares) = generate_shares(secret, numshares, threshold, 0, rng)?;

    let keypairs = shares
        .iter()
        .map(|share| KeyPair {
            secret: share.value,
            public: &constants::RISTRETTO_BASEPOINT_TABLE * &share.value,
            group_public: shares_com.commitment[0],
            index: share.receiver_index,
        })
        .collect();

    Ok((shares_com, keypairs))
}

/// keygen_begin is performed by each participant to initialize a Pedersen
///
/// This function assumes there is an additional layer which performs the
/// distribution of shares to their intended participants.
pub fn keygen_begin(
    numshares: u32,
    threshold: u32,
    generator_index: u32,
    rng: &mut ThreadRng,
) -> Result<(KeyGenDKGProposedCommitment, Vec<Share>), &'static str> {
    let secret = Scalar::random(rng);
    let (shares_com, shares) = generate_shares(secret, numshares, threshold, generator_index, rng)?;

    let r = Scalar::random(rng);
    let r_pub = &constants::RISTRETTO_BASEPOINT_TABLE * &r;

    let c = gen_c("keygen begin", r_pub);
    let z = r + secret * c;

    let dkg_commitment = KeyGenDKGProposedCommitment {
        index: generator_index,
        shares_commitment: shares_com,
        zkp: Signature { r: r_pub, z: z },
    };

    Ok((dkg_commitment, shares))
}

/// keygen_receive_commitments_and_validate_peers gathers commitments from
/// peers and validates the zero knowledge proof of knowledge for the peer's
/// secret term. It returns a list of all participants who failed the check,
/// a list of commitments for the peers that remain in a valid state,
/// and an error term.
///
/// Here, we return a DKG commitmentment that is explicitly marked as valid,
/// to ensure that this step of the protocol is performed before going on to
/// keygen_finalize
pub fn keygen_receive_commitments_and_validate_peers(
    peer_commitments: Vec<KeyGenDKGProposedCommitment>,
) -> (Vec<u32>, Vec<KeyGenDKGCommitment>) {
    let mut invalid_peer_ids = Vec::new();
    let mut valid_peer_commitments: Vec<KeyGenDKGCommitment> =
        Vec::with_capacity(peer_commitments.len());

    for commitment in peer_commitments {
        if !validate(
            "keygen begin",
            &commitment.zkp,
            commitment.get_commitment_to_secret(),
        )
        .is_ok()
        {
            invalid_peer_ids.push(commitment.index);
        } else {
            valid_peer_commitments.push(KeyGenDKGCommitment {
                index: commitment.index,
                shares_commitment: commitment.shares_commitment,
            });
        }
    }

    (invalid_peer_ids, valid_peer_commitments)
}

/// keygen_finalize finalizes the distributed key generation protocol.
/// It is performed once per participant.
pub fn keygen_finalize(
    index: u32,
    shares: &Vec<Share>,
    commitments: &Vec<KeyGenDKGCommitment>,
) -> Result<KeyPair, &'static str> {
    // first, verify the integrity of the shares
    for share in shares {
        let commitment = match commitments
            .iter()
            .find(|comm| comm.index == share.generator_index)
        {
            Some(x) => x,
            None => return Err("Received share with no corresponding commitment"),
        };
        verify_share(share, &commitment.shares_commitment)?;
    }

    let secret = shares.iter().fold(Scalar::zero(), |acc, x| acc + x.value);

    let public = &constants::RISTRETTO_BASEPOINT_TABLE * &secret;

    let group_public = commitments
        .iter()
        .map(|c| c.shares_commitment.commitment[0])
        .fold(RistrettoPoint::identity(), |acc, x| acc + x);

    Ok(KeyPair {
        index,
        secret,
        public,
        group_public,
    })
}

/// Create secret shares for a given secret. This function accepts a secret to
/// generate shares from. While in FROST this secret should always be generated
/// randomly, we allow this secret to be specified for this internal function
/// for testability
fn generate_shares(
    secret: Scalar,
    numshares: u32,
    threshold: u32,
    generator_index: u32,
    rng: &mut rand::rngs::ThreadRng,
) -> Result<(SharesCommitment, Vec<Share>), &'static str> {
    if threshold < 1 {
        return Err("Threshold cannot be 0");
    }
    if numshares < 1 {
        return Err("Number of shares cannot be 0");
    }
    if threshold > numshares {
        return Err("Threshold cannot exceed numshares");
    }

    let numcoeffs = threshold - 1;

    let mut coefficients: Vec<Scalar> = Vec::with_capacity(numcoeffs as usize);

    let mut shares: Vec<Share> = Vec::with_capacity(numshares as usize);

    let mut commitment: Vec<RistrettoPoint> = Vec::with_capacity(threshold as usize);

    for _ in 0..numcoeffs {
        coefficients.push(Scalar::random(rng));
    }

    commitment.push(&constants::RISTRETTO_BASEPOINT_TABLE * &secret);
    for c in &coefficients {
        commitment.push(&constants::RISTRETTO_BASEPOINT_TABLE * &c);
    }

    for index in 1..numshares + 1 {
        // Evaluate the polynomial with `secret` as the constant term
        // and `coeffs` as the other coefficients at the point x=share_index
        // using Horner's method
        let scalar_index = Scalar::from(index);
        let mut value = Scalar::zero();
        for i in (0..numcoeffs).rev() {
            value += &coefficients[i as usize];
            value *= scalar_index;
        }
        value += secret;
        shares.push(Share {
            generator_index: generator_index,
            receiver_index: index,
            value: value,
        });
    }
    Ok((SharesCommitment { commitment }, shares))
}

/// Verify that a share is consistent with a commitment.
fn verify_share(share: &Share, com: &SharesCommitment) -> Result<(), &'static str> {
    let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &share.value;

    let x = Scalar::from(share.receiver_index);

    let (_, result) = com.commitment.iter().fold(
        (Scalar::one(), RistrettoPoint::identity()),
        |(x_to_the_i, sum_so_far), comm_i| (x_to_the_i * x, sum_so_far + x_to_the_i * comm_i),
    );

    match f_result == result {
        true => Ok(()),
        false => Err("Share is invalid."),
    }
}

#[cfg(test)]
mod tests {
    use crate::keygen::*;
    use std::collections::HashMap;

    #[test]
    fn keygen_with_dkg_simple() {
        let mut rng: ThreadRng = rand::thread_rng();

        let num_shares = 5;
        let threshold = 3;

        let mut participant_shares: HashMap<u32, Vec<Share>> =
            HashMap::with_capacity(num_shares as usize);
        let mut participant_commitments: Vec<KeyGenDKGProposedCommitment> =
            Vec::with_capacity(num_shares as usize);

        for index in 1..num_shares + 1 {
            let (shares_com, shares) =
                keygen_begin(num_shares, threshold, index, &mut rng).unwrap();
            assert!(shares.len() == (num_shares as usize));

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
            participant_commitments.push(shares_com);
        }

        let (invalid_peer_ids, valid_commitments) =
            keygen_receive_commitments_and_validate_peers(participant_commitments);
        assert!(invalid_peer_ids.len() == 0);

        // now, finalize the protocol
        for index in 1..num_shares + 1 {
            let res = keygen_finalize(index, &participant_shares[&index], &valid_commitments);
            assert!(res.is_ok());
        }
    }

    #[test]
    fn keygen_with_dkg_invalid_secret_commitment() {
        let mut rng: ThreadRng = rand::thread_rng();

        let num_shares = 5;
        let threshold = 3;

        let mut participant_commitments: Vec<KeyGenDKGProposedCommitment> =
            Vec::with_capacity(num_shares as usize);

        for index in 1..num_shares + 1 {
            let (com, _) = keygen_begin(num_shares, threshold, index, &mut rng).unwrap();

            participant_commitments.push(com);
        }

        // now, set the first commitments to be invalid
        participant_commitments[0].shares_commitment.commitment[0] = RistrettoPoint::identity();
        let invalid_participant_id = participant_commitments[0].index;

        // now, ensure that this participant is marked as invalid
        let (invalid_ids, valid_coms) =
            keygen_receive_commitments_and_validate_peers(participant_commitments);
        assert!(invalid_ids.len() == 1);
        assert!(invalid_ids[0] == invalid_participant_id);
        assert!(valid_coms.len() == ((num_shares - 1) as usize));
    }

    /// Reconstruct the secret from enough (at least the threshold) already-verified shares.
    pub fn reconstruct_secret(shares: &Vec<Share>) -> Result<Scalar, &'static str> {
        let numshares = shares.len();

        if numshares < 1 {
            return Err("No shares provided");
        }

        let mut lagrange_coeffs: Vec<Scalar> = Vec::with_capacity(numshares);

        for i in 0..numshares {
            let mut num = Scalar::one();
            let mut den = Scalar::one();
            for j in 0..numshares {
                if j == i {
                    continue;
                }
                num *= Scalar::from(shares[j].receiver_index);
                den *=
                    Scalar::from(shares[j].receiver_index) - Scalar::from(shares[i].receiver_index);
            }
            if den == Scalar::zero() {
                return Err("Duplicate shares provided");
            }
            lagrange_coeffs.push(num * den.invert());
        }

        let mut secret = Scalar::zero();

        for i in 0..numshares {
            secret += lagrange_coeffs[i] * shares[i].value;
        }

        Ok(secret)
    }

    #[test]
    fn share_simple() {
        let s = Scalar::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let (com, shares) = generate_shares(s, 5, 2, 0, &mut rng).unwrap();
        assert!(shares.len() == 5);
        assert!(com.commitment.len() == 2);

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        recshares.push(shares[3]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
        assert_eq!(recres.unwrap(), s);
    }

    #[test]
    fn share_not_enough() {
        let s = Scalar::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, shares) = generate_shares(s, 5, 2, 0, &mut rng).unwrap();

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
        assert_ne!(recres.unwrap(), s);
    }

    #[test]
    fn share_dup() {
        let s = Scalar::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, shares) = generate_shares(s, 5, 2, 0, &mut rng).unwrap();

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        recshares.push(shares[1]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_err());
        assert_eq!(recres.err(), Some("Duplicate shares provided"));
    }

    #[test]
    fn share_badparams() {
        let s = Scalar::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        {
            let res = generate_shares(s, 5, 0, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Threshold cannot be 0"));
        }
        {
            let res = generate_shares(s, 0, 3, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Number of shares cannot be 0"));
        }
        {
            let res = generate_shares(s, 1, 3, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Threshold cannot exceed numshares"));
        }
    }

    #[test]
    fn share_commitment_valid() {
        let s = Scalar::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let (com, shares) = generate_shares(s, 8, 3, 0, &mut rng).unwrap();

        for share in shares {
            let is_valid = verify_share(&share, &com);
            assert!(is_valid.is_ok());
        }
    }

    #[test]
    fn share_commitment_invalid() {
        let s1 = Scalar::from(42u32);
        let s2 = Scalar::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, shares1) = generate_shares(s1, 8, 3, 0, &mut rng).unwrap();

        let (com2, _) = generate_shares(s2, 8, 3, 0, &mut rng).unwrap();

        for share in shares1 {
            // test that commitments to a different set of shares fails
            let is_valid = verify_share(&share, &com2);
            assert!(!is_valid.is_ok());
        }
    }
}
