//! Pure enrollment delivery: public RSA encryption only. Transport authentication,
//! durable storage, single-use policy and device admission belong to the caller.
use crate::policy::Res;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rsa::{
    Oaep, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    traits::PublicKeyParts,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const REQUEST: &[u8; 4] = b"RER1";
const ENVELOPE: &[u8; 4] = b"REE1";
const RECORD: &[u8; 4] = b"RES1";
const ACK: &[u8; 4] = b"REA1";
const FINAL: &[u8; 4] = b"REF1";
const MAX_REQUEST: usize = 2048;
const MAX_ENVELOPE: usize = 12288;
const MAX_RECORD: usize = 16384;
const DOMAIN: &[u8] = b"readb-enrollment-delivery-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"readb-enrollment-receipt-v1\0";
fn error() -> String {
    "enrollment_delivery_invalid".into()
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn blob(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
struct Read<'a> {
    bytes: &'a [u8],
}
impl<'a> Read<'a> {
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        if n > self.bytes.len() {
            return Err(error());
        }
        let (v, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(v)
    }
    fn magic(&mut self, value: &[u8]) -> Res<()> {
        if self.take(value.len())? != value {
            return Err(error());
        }
        Ok(())
    }
    fn blob(&mut self, limit: usize) -> Res<&'a [u8]> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| error())?) as usize;
        if n > limit {
            return Err(error());
        }
        self.take(n)
    }
    fn end(&self) -> Res<()> {
        if !self.bytes.is_empty() {
            Err(error())
        } else {
            Ok(())
        }
    }
}
fn unhex(value: &str) -> Res<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| error())?;
    }
    Ok(out)
}
/// Public exact server/device/transaction binding; no credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct Context {
    bytes: Vec<u8>,
    device: String,
}
impl Context {
    pub fn new(server: &str, device: &str, transaction: &str) -> Res<Self> {
        if !readb_protocol::valid_device_id(device) {
            return Err(error());
        }
        let mut bytes = unhex(server)?.to_vec();
        bytes.extend_from_slice(&unhex(transaction)?);
        blob(&mut bytes, device.as_bytes());
        Ok(Self {
            bytes,
            device: device.into(),
        })
    }
    fn parse(bytes: &[u8]) -> Res<Self> {
        let mut r = Read { bytes };
        r.take(64)?;
        let id = std::str::from_utf8(r.blob(64)?).map_err(|_| error())?;
        r.end()?;
        if !readb_protocol::valid_device_id(id) {
            return Err(error());
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            device: id.into(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
fn request(bytes: &[u8]) -> Res<RsaPublicKey> {
    if bytes.len() > MAX_REQUEST {
        return Err(error());
    }
    let mut r = Read { bytes };
    r.magic(REQUEST)?;
    r.take(64)?;
    let der = r.blob(1024)?;
    r.end()?;
    let key = RsaPublicKey::from_public_key_der(der).map_err(|_| error())?;
    if !matches!(key.n().bits(), 3072 | 4096)
        || key.e() != &rsa::BigUint::from(65537u32)
        || key.to_public_key_der().map_err(|_| error())?.as_bytes() != der
    {
        return Err(error());
    }
    Ok(key)
}
fn aad(context: &Context, request: &[u8], commitment: &[u8]) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(context.bytes());
    out.extend_from_slice(&digest(request));
    out.extend_from_slice(commitment);
    out
}
fn check_envelope(context: &Context, req: &[u8], envelope: &[u8], commitment: &[u8]) -> Res<()> {
    if envelope.len() > MAX_ENVELOPE {
        return Err(error());
    }
    let key = request(req)?;
    let mut r = Read { bytes: envelope };
    r.magic(ENVELOPE)?;
    r.magic(&digest(req))?;
    r.magic(&digest(context.bytes()))?;
    r.magic(commitment)?;
    if r.blob(512)?.len() != key.size() {
        return Err(error());
    }
    r.take(12)?;
    let ciphertext = r.blob(8248)?;
    if ciphertext.len() < 56 {
        return Err(error());
    }
    r.end()
}
/// Private server recovery material. It must be stored only in the existing
/// private durable journal; a receipt verification is not a storage assertion.
/// ```compile_fail
/// fn leak(p: readb::enrollment_delivery::Prepared) { let _ = format!("{p:?}"); }
/// ```
/// ```compile_fail
/// fn leak(p: readb::enrollment_delivery::Prepared) { let _ = serde_json::to_vec(&p); }
/// ```
pub struct Prepared {
    context: Context,
    request: Vec<u8>,
    envelope: Vec<u8>,
    secret: Zeroizing<[u8; 32]>,
}
impl Prepared {
    pub fn seal(context: &Context, req: &[u8], profile: &[u8]) -> Res<Self> {
        if profile.len() > 8192 {
            return Err(error());
        }
        let mut decoded: readb_protocol::Profile =
            serde_json::from_slice(profile).map_err(|_| error())?;
        let valid = decoded.validate().is_ok() && decoded.device_id == context.device;
        decoded.token.zeroize();
        decoded.private_key.zeroize();
        if !valid {
            return Err(error());
        }
        let public = request(req)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        let mut key = Zeroizing::new([0u8; 32]);
        let mut iv = [0; 12];
        OsRng.try_fill_bytes(secret.as_mut()).map_err(|_| error())?;
        OsRng.try_fill_bytes(key.as_mut()).map_err(|_| error())?;
        OsRng.try_fill_bytes(&mut iv).map_err(|_| error())?;
        let commitment = digest(secret.as_ref());
        let mut plaintext = Zeroizing::new(b"REP1".to_vec());
        plaintext.extend_from_slice(secret.as_ref());
        blob(&mut plaintext, profile);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| error())?;
        let nonce = Nonce::from(iv);
        let sealed = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad(context, req, &commitment),
                },
            )
            .map_err(|_| error())?;
        let padding = Oaep::new_with_mgf_hash::<sha2_oaep::Sha256, sha1_oaep::Sha1>();
        let wrapped = public
            .encrypt(&mut OsRng, padding, key.as_ref())
            .map_err(|_| error())?;
        let mut envelope = ENVELOPE.to_vec();
        envelope.extend_from_slice(&digest(req));
        envelope.extend_from_slice(&digest(context.bytes()));
        envelope.extend_from_slice(&commitment);
        blob(&mut envelope, &wrapped);
        envelope.extend_from_slice(&iv);
        blob(&mut envelope, &sealed);
        check_envelope(context, req, &envelope, &commitment)?;
        Ok(Self {
            context: context.clone(),
            request: req.to_vec(),
            envelope,
            secret,
        })
    }
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn private_bytes(&self) -> Res<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(RECORD.to_vec());
        blob(&mut out, self.context.bytes());
        blob(&mut out, &self.request);
        out.extend_from_slice(self.secret.as_ref());
        blob(&mut out, &self.envelope);
        let checksum = digest(&out);
        out.extend_from_slice(&checksum);
        if out.len() > MAX_RECORD {
            return Err(error());
        }
        Ok(out)
    }
    pub fn restore(bytes: &[u8]) -> Res<Self> {
        if bytes.len() > MAX_RECORD || bytes.len() < 32 {
            return Err(error());
        }
        let (content, checksum) = bytes.split_at(bytes.len() - 32);
        if !bool::from(digest(content).as_slice().ct_eq(checksum)) {
            return Err(error());
        }
        let mut r = Read { bytes: content };
        r.magic(RECORD)?;
        let context = Context::parse(r.blob(132)?)?;
        let req = r.blob(MAX_REQUEST)?.to_vec();
        let secret = Zeroizing::new(<[u8; 32]>::try_from(r.take(32)?).map_err(|_| error())?);
        let envelope = r.blob(MAX_ENVELOPE)?.to_vec();
        r.end()?;
        check_envelope(&context, &req, &envelope, &digest(secret.as_ref()))?;
        Ok(Self {
            context,
            request: req,
            envelope,
            secret,
        })
    }
    fn receipt(&self, kind: &[u8; 4]) -> Res<Vec<u8>> {
        let mut frame = kind.to_vec();
        frame.extend_from_slice(&digest(&self.request));
        frame.extend_from_slice(&digest(self.context.bytes()));
        frame.extend_from_slice(&digest(&self.envelope));
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.secret.as_ref())
            .map_err(|_| error())?;
        mac.update(RECEIPT_DOMAIN);
        mac.update(&frame);
        frame.extend_from_slice(&mac.finalize().into_bytes());
        Ok(frame)
    }
    pub fn verify_ack(&self, ack: &[u8]) -> Res<()> {
        if !bool::from(self.receipt(ACK)?.as_slice().ct_eq(ack)) {
            return Err(error());
        }
        Ok(())
    }
    /// Caller must durably finalize enrollment before releasing this receipt.
    pub fn final_receipt(&self, ack: &[u8]) -> Res<Vec<u8>> {
        self.verify_ack(ack)?;
        self.receipt(FINAL)
    }
}
