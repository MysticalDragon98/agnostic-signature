import { publicEncrypt, constants } from 'crypto';

/**
 * Encrypts data using an RSA public key
 * Note: Due to RSA limitations, the data length must be less than the key size minus padding
 * For 2048-bit key, maximum data length is about 214 bytes with RSA-OAEP
 */
export function encryptWithPublicKey(data: Buffer, publicKeyPem: string): Buffer {
    const encryptedData = publicEncrypt(
        {
            key: publicKeyPem,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        data
    );
    
    return encryptedData;
}