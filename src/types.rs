use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

pub type Secret = Scalar;
pub type KeyGenCommitment = Vec<RistrettoPoint>;
pub type GroupSigningCommitment = RistrettoPoint;

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
    pub signer_pubkey: RistrettoPoint,
}

#[derive(Copy, Clone)]
pub struct SigningCommitment {
    pub d_comm: RistrettoPoint,
    pub e_comm: RistrettoPoint,
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
    pub public: RistrettoPoint,
}

#[derive(Copy, Clone)]
pub struct Share {
    pub index: usize,
    pub value: Scalar,
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub secret: Scalar,
    pub public: RistrettoPoint,
    pub index: usize,
}

#[derive(Copy, Clone)]
pub struct Signature {
    pub r: RistrettoPoint,
    pub z: Scalar,
}
