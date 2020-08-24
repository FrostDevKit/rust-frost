use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

pub type Secret = Scalar;
pub type KeyGenCommitment = Vec<EdwardsPoint>;
pub type GroupSigningCommitment = EdwardsPoint;

#[derive(Clone)]
pub struct SigningPackage {
    pub items: Vec<SigningItem>,
}

#[derive(Copy, Clone)]
pub struct SigningItem {
    pub index: usize,
    pub commitment: SigningCommitment,
}

#[derive(Copy, Clone)]
pub struct SigningResponse {
    pub response: Scalar,
    pub signer_pubkey: EdwardsPoint,
}

#[derive(Copy, Clone)]
pub struct SigningCommitment {
    pub d_comm: EdwardsPoint,
    pub e_comm: EdwardsPoint,
}

#[derive(Copy, Clone)]
pub struct Nonce {
    pub d: NonceInstance,
    pub e: NonceInstance,
    pub is_dirty: bool,
}

#[derive(Copy, Clone)]
pub struct NonceInstance {
    pub secret: Scalar,
    pub public: EdwardsPoint,
}

#[derive(Copy, Clone)]
pub struct Share {
    pub index: usize,
    pub value: Scalar,
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub secret: Scalar,
    pub public: EdwardsPoint,
    pub index: usize,
}

#[derive(Copy, Clone)]
pub struct Signature {
    pub r: EdwardsPoint,
    pub z: Scalar,
}
