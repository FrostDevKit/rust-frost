use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use types::*;

/// Create secret shares for a given secret.
pub fn generate_shares(
    secret: Secret,
    numshares: usize,
    threshold: usize,
    rng: &mut rand::rngs::ThreadRng,
) -> Result<(KeyGenCommitment, Vec<Share>), &'static str> {
    if threshold < 1 {
        return Err("Threshold cannot be 0");
    }
    if numshares < 1 {
        return Err("Number of shares cannot be 0");
    }
    if threshold > numshares {
        return Err("Threshold cannot exceed numshares");
    }

    let numcoeffs = (threshold - 1) as usize;

    let mut coefficients: Vec<Scalar> = Vec::with_capacity(numcoeffs);

    let mut shares: Vec<Share> = Vec::with_capacity(numshares as usize);

    let mut commitment: KeyGenCommitment = Vec::with_capacity(threshold as usize);

    for _ in 0..numcoeffs {
        coefficients.push(Scalar::random(rng));
    }

    for share_index in 1..numshares + 1 {
        // Evaluate the polynomial with `secret` as the constant term
        // and `coeffs` as the other coefficients at the point x=share_index
        // using Horner's method
        let scalar_index = Scalar::from(share_index as u32);
        let mut value = Scalar::zero();
        for i in (0..numcoeffs).rev() {
            value += coefficients[i];
            value *= scalar_index;
        }
        value += secret;
        shares.push(Share {
            index: share_index,
            value: value,
        });
    }

    commitment.push(ED25519_BASEPOINT_POINT * secret);
    for c in coefficients {
        commitment.push(ED25519_BASEPOINT_POINT * c);
    }

    Ok((commitment, shares))
}

/// Verify that a share is consistent with a commitment.
pub fn verify_share(share: &Share, commitment: &KeyGenCommitment) -> Result<bool, &'static str> {
    let f_result = ED25519_BASEPOINT_POINT * share.value;

    let x = Scalar::from(share.index as u32);

    let (_, result) = commitment.iter().fold(
        (Scalar::one(), EdwardsPoint::identity()),
        |(x_to_the_i, sum_so_far), comm_i| (x_to_the_i * x, sum_so_far + x_to_the_i * comm_i),
    );

    let is_valid = f_result == result;
    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use crate::vss::*;
    use rand::rngs::ThreadRng;

    /// Reconstruct the secret from enough (at least the threshold) already-verified shares.
    pub fn reconstruct_secret(shares: &Vec<Share>) -> Result<Secret, &'static str> {
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
                num *= Scalar::from(shares[j].index as u32);
                den *= Scalar::from(shares[j].index as u32) - Scalar::from(shares[i].index as u32);
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
        let s = Secret::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let res = generate_shares(s, 5, 2, &mut rng);
        assert!(res.is_ok());
        let (com, shares) = res.unwrap();
        assert!(shares.len() == 5);
        assert!(com.len() == 2);

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        recshares.push(shares[3]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
        assert_eq!(recres.unwrap(), s);
    }

    #[test]
    fn share_not_enough() {
        let s = Secret::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let res = generate_shares(s, 5, 2, &mut rng);
        assert!(res.is_ok());
        let (_, shares) = res.unwrap();

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
        assert_ne!(recres.unwrap(), s);
    }

    #[test]
    fn share_dup() {
        let s = Secret::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let res = generate_shares(s, 5, 2, &mut rng);
        assert!(res.is_ok());
        let (_, shares) = res.unwrap();

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(shares[1]);
        recshares.push(shares[1]);
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_err());
        assert_eq!(recres.err(), Some("Duplicate shares provided"));
    }

    #[test]
    fn share_badparams() {
        let s = Secret::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        {
            let res = generate_shares(s, 5, 0, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Threshold cannot be 0"));
        }
        {
            let res = generate_shares(s, 0, 3, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Number of shares cannot be 0"));
        }
        {
            let res = generate_shares(s, 1, 3, &mut rng);
            assert!(res.is_err());
            assert_eq!(res.err(), Some("Threshold cannot exceed numshares"));
        }
    }

    #[test]
    fn share_commitment_valid() {
        let s = Secret::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let res = generate_shares(s, 8, 3, &mut rng);
        assert!(res.is_ok());
        let (com, shares) = res.unwrap();

        for share in shares {
            let is_valid = verify_share(&share, &com);
            assert!(is_valid.is_ok());
            assert!(is_valid.unwrap());
        }
    }

    #[test]
    fn share_commitment_invalid() {
        let s1 = Secret::from(42u32);
        let s2 = Secret::from(42u32);
        let mut rng: ThreadRng = rand::thread_rng();

        let res1 = generate_shares(s1, 8, 3, &mut rng);
        assert!(res1.is_ok());
        let (_, shares1) = res1.unwrap();

        let res2 = generate_shares(s2, 8, 3, &mut rng);
        assert!(res2.is_ok());
        let (com2, _) = res2.unwrap();

        for share in shares1 {
            // test that commitments to a different set of shares fails
            let is_valid = verify_share(&share, &com2);
            assert!(is_valid.is_ok());
            assert_ne!(is_valid.unwrap(), true);
        }
    }
}
