/**
 * Extracts signature and data from signed buffer
 * @param signedData Buffer containing signature + data
 * @returns Separated signature and data
 */
export function extractSignatureAndData(signedData: Buffer): { signature: Buffer; data: Buffer } {
    // For 2048-bit RSA key, signature is always 256 bytes
    const SIGNATURE_SIZE = 256;
    
    if (signedData.length <= SIGNATURE_SIZE) {
        throw new Error('Invalid signed data: buffer too short');
    }

    return {
        signature: signedData.subarray(0, SIGNATURE_SIZE),
        data: signedData.subarray(SIGNATURE_SIZE)
    };
}

