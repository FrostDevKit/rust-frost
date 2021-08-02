use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use keygen::*;

/// generates the langrange coefficient for the ith participant. This allows
/// for performing Lagrange interpolation, which underpins threshold secret
/// sharing schemes based on Shamir secret sharing.
pub fn get_lagrange_coeff(
    x_coord: u32,
    signer_index: u32,
    all_signer_indices: &Vec<u32>,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in all_signer_indices {
        if *j == signer_index {
            continue;
        }
        num *= Scalar::from(*j) - Scalar::from(x_coord);
        den *= Scalar::from(*j) - Scalar::from(signer_index);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

pub fn get_ith_pubkey(index: u32, commitments: &Vec<KeyGenDKGCommitment>) -> RistrettoPoint {
    let mut ith_pubkey = RistrettoPoint::identity();
    let term = Scalar::from(index);

    // iterate over each commitment
    for commitment in commitments {
        let mut result = RistrettoPoint::identity();
        let t = commitment.shares_commitment.commitment.len() as u32;
        // iterate  over each element in the commitment
        for (inner_index, comm_i) in commitment
            .shares_commitment
            .commitment
            .iter()
            .rev()
            .enumerate()
        {
            result += comm_i;

            // handle constant term
            if inner_index as u32 != t - 1 {
                result *= term;
            }
        }

        ith_pubkey += result;
    }

    ith_pubkey
}
//    let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &share.value;
//
//    let term = Scalar::from(share.receiver_index);
//    let mut result = RistrettoPoint::identity();
//
//    // Thanks to isis lovecruft for their simplification to Horner's method;
//    // including it here for readability. Their implementation of FROST can
//    // be found here: github.com/isislovecruft/frost-dalek
//    for (index, comm_i) in com.commitment.iter().rev().enumerate() {
//        result += comm_i;
//
//        if index != com.commitment.len() - 1 {
//            result *= term;
//        }
//    }
//
//    if !(f_result == result) {
//        return Err("Share is invalid.");
//    }
