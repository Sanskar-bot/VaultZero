/**
 * Encoding Utilities — Base64, Hex, UTF-8 ↔ Uint8Array conversions
 *
 * These are used throughout VaultZero to convert between:
 * - Uint8Array (what crypto APIs produce/consume)
 * - Base64 strings (what we store/transmit)
 * - Hex strings (used for SHA-256 hashes, token hashing)
 * - UTF-8 strings (what we JSON.stringify for vault contents)
 *
 * All functions are pure, synchronous, and side-effect free.
 * None of them perform any cryptographic operations.
 */

/**
 * Encode a Uint8Array to a standard Base64 string.
 * Used to serialize encrypted blobs for storage/transmission.
 */
export function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

/**
 * Decode a Base64 string back to a Uint8Array.
 * Used to deserialize encrypted blobs from storage/transmission.
 */
export function fromBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}

/**
 * Encode a Uint8Array to a lowercase hex string.
 * Used for SHA-256 hash representations and token hashing.
 */
export function toHex(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}

/**
 * Decode a hex string back to a Uint8Array.
 * Accepts both lowercase and uppercase hex characters.
 */
export function fromHex(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "hex"));
}

/**
 * Encode a UTF-8 string to a Uint8Array.
 * Used before encrypting plaintext (strings → bytes → AES-GCM).
 */
export function utf8Encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Decode a Uint8Array back to a UTF-8 string.
 * Used after decrypting ciphertext (AES-GCM → bytes → string).
 */
export function utf8Decode(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}
