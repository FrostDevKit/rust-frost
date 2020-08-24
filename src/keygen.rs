use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::ThreadRng;
use std::collections::HashMap;

use types::*;
use vss::generate_shares;

/// keygen_with_dealer generates shares and distributes then via a trusted dealer.
pub fn keygen_with_dealer(
    numshares: usize,
    threshold: usize,
    rng: &mut ThreadRng,
) -> Result<(KeyGenCommitment, HashMap<u32, KeyPair>, EdwardsPoint), &'static str> {
    let secret = Scalar::random(rng);

    let res = generate_shares(secret, numshares, threshold, rng);
    if !res.is_ok() {
        return Err("Error when performing keygen");
    }

    let mut keypairs: HashMap<u32, KeyPair> = HashMap::with_capacity(numshares as usize);
    let (com, shares) = res.unwrap();
    for index in 0..shares.len() {
        let share = shares[index];
        let public_key = ED25519_BASEPOINT_POINT * share.value;
        keypairs.insert(
            share.index as u32,
            KeyPair {
                secret: share.value,
                public: public_key,
                index: share.index,
            },
        );
    }

    let group_pub_key = ED25519_BASEPOINT_POINT * secret; // TODO this will change with the DKG

    Ok((com, keypairs, group_pub_key))
}

#[cfg(test)]
mod tests {
    use crate::keygen::*;

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
    fn keygen_with_dealer_simple() {
        let mut rng: ThreadRng = rand::thread_rng();
        let res = keygen_with_dealer(5, 2, &mut rng);
        assert!(res.is_ok());
        let (com, shares, _) = res.unwrap();
        assert!(shares.len() == 5);
        assert!(com.len() == 2);

        let mut recshares: Vec<Share> = Vec::new();
        recshares.push(Share {
            index: 1,
            value: shares[&(1 as u32)].secret,
        });
        recshares.push(Share {
            index: 3,
            value: shares[&(3 as u32)].secret,
        });
        let recres = reconstruct_secret(&recshares);
        assert!(recres.is_ok());
    }
}
