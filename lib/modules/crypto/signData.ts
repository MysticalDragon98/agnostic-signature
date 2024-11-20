import { createPrivateKey, createSign  } from 'crypto';
import { derToPem } from './derToPem';

export interface SignatureResult {
    data: Buffer;
    signature: Buffer;
}

/**
 * Signs data using RSA private key
 * @param data Buffer to sign
 * @param privateKey RSA private key in DER format
 * @returns Signature buffer
 */
export function signData(data: Buffer, privateKeyPem: string): Buffer {
    const signer = createSign('SHA256');
    signer.update(data);

    return Buffer.concat([
        signer.sign(privateKeyPem),
        data
    ]);
}
