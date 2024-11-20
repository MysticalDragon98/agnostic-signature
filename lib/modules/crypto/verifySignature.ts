import { createVerify } from "crypto";
import { extractSignatureAndData } from "./extractSignatureAndData";

/**
 * Verifies if a signed buffer was signed with the private key corresponding to the given public key
 * @param signedData Buffer containing signature + data
 * @param publicKeyPem The public key in PEM format
 * @returns boolean indicating if the signature is valid for this public key
 */
export function verifySignature(signedData: Buffer, publicKeyPem: string): boolean {
    try {
        const { signature, data } = extractSignatureAndData(signedData);

        const verifier = createVerify('SHA256');
        verifier.update(data);
        
        return verifier.verify(publicKeyPem, signature);
    } catch (error) {
        return false;
    }
}