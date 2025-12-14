import * as crypto from 'crypto';

/**
 * AES-256-GCM Encryption Utility
 * 
 * SECURITY: Uses authenticated encryption (GCM mode) to prevent bit-flipping attacks.
 * Generates a unique IV for each encryption operation.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits

export interface EncryptedPayload {
  iv: string;
  content: string;
  tag: string;
}

/**
 * Derives a 32-byte key from a secret using SHA-256.
 * For production, consider using PBKDF2/scrypt with a salt.
 */
function deriveKey(secret: string): Buffer {
  return crypto.createHash('sha256').update(secret).digest();
}

export const encryption = {
  /**
   * Encrypts plaintext using AES-256-GCM.
   * @param plaintext - The string to encrypt.
   * @param secretKey - The secret key (any length, will be hashed to 256 bits).
   * @returns Encrypted payload with IV, ciphertext, and authentication tag.
   */
  encrypt: (plaintext: string, secretKey: string): EncryptedPayload => {
    if (!plaintext || !secretKey) {
      throw new Error('Plaintext and secretKey are required for encryption.');
    }
    
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(secretKey);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    
    return {
      iv: iv.toString('hex'),
      content: encrypted.toString('hex'),
      tag: cipher.getAuthTag().toString('hex')
    };
  },

  /**
   * Decrypts an encrypted payload using AES-256-GCM.
   * @param payload - The encrypted payload (iv, content, tag).
   * @param secretKey - The secret key used during encryption.
   * @returns Decrypted plaintext.
   * @throws Error if decryption fails (wrong key or tampered data).
   */
  decrypt: (payload: EncryptedPayload, secretKey: string): string => {
    if (!payload?.iv || !payload?.content || !payload?.tag || !secretKey) {
      throw new Error('Invalid payload or missing secretKey for decryption.');
    }
    
    const key = deriveKey(secretKey);
    const iv = Buffer.from(payload.iv, 'hex');
    const encryptedText = Buffer.from(payload.content, 'hex');
    const authTag = Buffer.from(payload.tag, 'hex');
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final()
    ]);
    
    return decrypted.toString('utf8');
  }
};
