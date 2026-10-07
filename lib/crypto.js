const crypto = require("node:crypto");
const { ethers } = require("ethers");

/**
 * End-to-end payload encryption between devices.
 * X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM. Public keys are distributed (and authenticated) through
 * the SecureMessaging contract, so a gateway or relay in the middle cannot swap keys.
 */

// DER prefix for a raw 32 byte X25519 public key wrapped as SubjectPublicKeyInfo.
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function generateEncryptionKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(X25519_SPKI_PREFIX.length);
  return { privateKey, publicKey: ethers.hexlify(raw) };
}

function importPublicKey(hex) {
  const raw = Buffer.from(ethers.getBytes(hex));
  if (raw.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function deriveKey(privateKey, peerPublicKeyHex, senderId, receiverId) {
  const shared = crypto.diffieHellman({ privateKey, publicKey: importPublicKey(peerPublicKeyHex) });
  const info = Buffer.from(`iot-secure-messaging:v1:${senderId}->${receiverId}`);
  return Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), info, 32));
}

/**
 * Encrypts a payload for the receiver. Returns a hex envelope `iv(12) | tag(16) | ciphertext`.
 * The sender/receiver IDs are bound as additional authenticated data.
 */
function encryptPayload({ privateKey, peerPublicKey, senderId, receiverId, plaintext }) {
  const key = deriveKey(privateKey, peerPublicKey, senderId, receiverId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`${senderId}->${receiverId}`));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return ethers.hexlify(Buffer.concat([iv, cipher.getAuthTag(), ciphertext]));
}

function decryptPayload({ privateKey, peerPublicKey, senderId, receiverId, envelope }) {
  const bytes = Buffer.from(ethers.getBytes(envelope));
  const iv = bytes.subarray(0, 12);
  const tag = bytes.subarray(12, 28);
  const ciphertext = bytes.subarray(28);
  const key = deriveKey(privateKey, peerPublicKey, senderId, receiverId);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(`${senderId}->${receiverId}`));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

module.exports = { generateEncryptionKeyPair, encryptPayload, decryptPayload };
