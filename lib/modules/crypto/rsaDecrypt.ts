import { constants, createDecipheriv, privateDecrypt } from "crypto";

export function rsaDecrypt(encryptedBuffer: Buffer, privateKeyPem: string): Buffer {
    // RSA-encrypted AES key length for 2048-bit RSA is 256 bytes
    const RSA_ENCRYPTED_KEY_LENGTH = 256;
    const IV_LENGTH = 16;

    // Extract the components from the combined buffer
    const encryptedKey = encryptedBuffer.subarray(0, RSA_ENCRYPTED_KEY_LENGTH);
    const iv = encryptedBuffer.subarray(
        RSA_ENCRYPTED_KEY_LENGTH,
        RSA_ENCRYPTED_KEY_LENGTH + IV_LENGTH
    );
    const encryptedData = encryptedBuffer.subarray(RSA_ENCRYPTED_KEY_LENGTH + IV_LENGTH);

    // Decrypt the AES key using RSA private key
    const aesKey = privateDecrypt(
        {
            key: privateKeyPem,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        encryptedKey
    );

    // Decrypt the data using AES
    const decipher = createDecipheriv('aes-256-cbc', aesKey, iv);
    const decryptedData = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final()
    ]);

    return decryptedData;
}