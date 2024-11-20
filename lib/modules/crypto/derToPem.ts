/**
 * Converts a DER buffer to PEM format
 */
export function derToPem(der: Buffer, type: 'public' | 'private'): string {
    const b64 = der.toString('base64');
    const formatted = b64.match(/.{1,64}/g)!.join('\n');
    if (type === 'public') {
        return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
    } else {
        return `-----BEGIN PRIVATE KEY-----\n${formatted}\n-----END PRIVATE KEY-----`;
    }
}
