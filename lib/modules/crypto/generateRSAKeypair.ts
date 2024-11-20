import { generateKeyPairSync, createSign, createVerify } from 'crypto';

// Interface for PEM key pair result
export interface RSAKeyPairResult {
    publicKey: string;  // PEM format
    privateKey: string; // PEM format
}

// Interface for the custom options
export interface RSAGeneratorOptions {
    modulusLength?: number;
    publicExponent?: number;
}

/**
 * Generates an RSA key pair in PEM format
 */
export function generateRSAKeyPair(options: RSAGeneratorOptions = {}): RSAKeyPairResult {
    const defaultOptions = {
        modulusLength: 2048,
        publicExponent: 0x10001,
    };

    // Merge options
    const finalOptions = {
        ...defaultOptions,
        ...options,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    };

    const { publicKey, privateKey } = generateKeyPairSync('rsa', finalOptions);

    return {
        publicKey: publicKey.toString(),
        privateKey: privateKey.toString()
    };
}