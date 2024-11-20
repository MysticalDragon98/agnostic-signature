import { encryptWithPublicKey } from "./encryptWithPublicKey";

/**
 * Encrypts data that's longer than the RSA key size by using
 * a hybrid encryption scheme (AES + RSA)
 */
export function rsaEncrypt(data: Buffer, publicKeyPem: string): Buffer {
    const { createCipheriv, randomBytes } = require('crypto');

    // Generate a random AES-256 key
    const aesKey = randomBytes(32);
    const iv = randomBytes(16);

    // Encrypt the AES key with RSA
    const encryptedKey = encryptWithPublicKey(aesKey, publicKeyPem);

    // Encrypt the data with AES
    const cipher = createCipheriv('aes-256-cbc', aesKey, iv);
    const encryptedData = Buffer.concat([
        cipher.update(data),
        cipher.final()
    ]);
    
    return Buffer.concat([
        encryptedKey.subarray(1),
        iv,
        encryptedData
    ]);
}

// <Buffer 1b 9e 5b 74 16 de 30 c1 e3 b5 97 f2 70 4e 90 57 33 df a6 02 86 20 46 11 79 62 bf e2 96 5f 54 48 27 7b a4 71 02 72 8d 52 c1 60 40 94 c9 27 ff 2e 4b 13 ... 589 more bytes>
// <Buffer 1b 83 4d bd ad a6 6a a1 6d a1 40 cc ba 7d f3 a4 93 49 90 de 23 c4 ea 74 52 e8 fa 8c cd 9a 7e 2d 68 03 e8 b3 c6 a1 f8 8d 45 11 31 f6 f4 5c 15 03 0b 67 ... 590 more bytes>
