import { RSAKeyPairResult, generateRSAKeyPair } from "../crypto/generateRSAKeypair";

export default function generateServicesKeys (services: string[]) {
    const keys: Record<string, RSAKeyPairResult> = {};

    services.forEach(service => {
        keys[service] = generateRSAKeyPair();
    });

    return keys;
}