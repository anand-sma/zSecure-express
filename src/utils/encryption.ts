import * as crypto from 'crypto';

/**
 * Enterprise Cryptography Module
 * 
 * Includes:
 * - Symmetric Encryption (AES-256-GCM)
 * - Asymmetric Helpers (RSA/ECC KeyGen)
 * - Hashing (Scrypt, PBKDF2, SHA-3)
 * - Data Masking
 * - Secure Randomness
 */

// --- Constants ---
const ALGO_AES = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 16;

export interface EncryptedPayload {
  iv: string;
  content: string;
  tag: string;
  aad?: string; // Additional Authenticated Data
  v?: number;   // Key Version for Rotation
}

export interface HashOptions {
  cost?: number;
  blockSize?: number;
  parallelization?: number;
}

export const encryption = {
  
  // =========================================================================
  // 1. Symmetric Encryption (AES-256-GCM)
  // =========================================================================
  
  /**
   * Encrypts data using AES-256-GCM.
   * Supports Additional Authenticated Data (AAD) for integrity binding.
   */
  encrypt: (plaintext: string, secretKey: string | Buffer, aad: string = ''): EncryptedPayload => {
    // Ensure key is 32 bytes
    const key = typeof secretKey === 'string' 
      ? crypto.scryptSync(secretKey, 'salt', 32) // Simple derivation if string
      : secretKey;

    if (key.length !== 32) throw new Error('Encryption Key must be 32 bytes.');

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGO_AES, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    
    if (aad) {
      cipher.setAAD(Buffer.from(aad, 'utf8'), { plaintextLength: Buffer.byteLength(plaintext) });
    }

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);

    return {
      iv: iv.toString('hex'),
      content: encrypted.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
      aad: aad || undefined
    };
  },

  /**
   * Decrypts AES-256-GCM payload.
   */
  decrypt: (payload: EncryptedPayload, secretKey: string | Buffer): string => {
    const key = typeof secretKey === 'string' 
      ? crypto.scryptSync(secretKey, 'salt', 32)
      : secretKey;
      
    const iv = Buffer.from(payload.iv, 'hex');
    const encryptedText = Buffer.from(payload.content, 'hex');
    const authTag = Buffer.from(payload.tag, 'hex');

    const decipher = crypto.createDecipheriv(ALGO_AES, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(authTag);
    
    if (payload.aad) {
      decipher.setAAD(Buffer.from(payload.aad, 'utf8'), { plaintextLength: encryptedText.length });
    }

    const decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  },

  // =========================================================================
  // 2. Hashing & Passwords (PBKDF2/Scrypt)
  // =========================================================================

  /**
   * Hashes a password using Scrypt (Memory Hard, resistant to ASIC/GPU).
   * Native Node.js alternative to Argon2.
   */
  hashPassword: async (password: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      const salt = crypto.randomBytes(SALT_LENGTH).toString('hex');
      // N=16384, r=8, p=1 defaults usually safe
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) reject(err);
        resolve(`${salt}:${derivedKey.toString('hex')}`);
      });
    });
  },

  /**
   * Verifies a password against a stored hash (salt:hash).
   */
  verifyPassword: async (password: string, storedHash: string): Promise<boolean> => {
    return new Promise((resolve, reject) => {
      const [salt, hash] = storedHash.split(':');
      if (!salt || !hash) return resolve(false);

      const hashBuffer = Buffer.from(hash, 'hex');
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) reject(err);
        resolve(crypto.timingSafeEqual(hashBuffer, derivedKey));
      });
    });
  },

  /**
   * SHA-3 (Keccak) Hashing for Data Integrity
   */
  hashData: (data: string, algo: 'sha3-256' | 'sha3-512' | 'sha256' = 'sha3-256'): string => {
    return crypto.createHash(algo).update(data).digest('hex');
  },

  // =========================================================================
  // 3. Data Masking & Anonymization
  // =========================================================================

  mask: {
    email: (email: string): string => {
      const  [user, domain] = email.split('@');
      if (!domain) return email; // Invalid
      const maskLen = Math.max(0, user.length - 2);
      return `${user.slice(0, 2)}${'*'.repeat(maskLen)}@${domain}`;
    },
    
    creditCard: (cc: string): string => {
      if (cc.length < 10) return cc;
      return `${'*'.repeat(cc.length - 4)}${cc.slice(-4)}`;
    },
    
    phone: (phone: string): string => {
      if (phone.length < 5) return phone;
      return `${'*'.repeat(phone.length - 4)}${phone.slice(-4)}`;
    }
  },

  // =========================================================================
  // 4. Randomness & Keys
  // =========================================================================

  randomToken: (length = 32): string => {
    return crypto.randomBytes(length).toString('hex');
  },

  randomUUID: (): string => {
     return crypto.randomUUID();
  },

  /**
   * Generates a new RSA Key Pair (2048 or 4096 bits)
   */
  generateKeyPair: (modulusLength: 2048 | 4096 = 2048): { publicKey: string, privateKey: string } => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
  }
};
