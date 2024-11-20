import bruteForceRSADecrypt from "./bruteForceRSADecrypt";
import { RSAKeyPairResult } from "./generateRSAKeypair";

export default function findCorrespondingServiceKey (serviceKeys: Record<string, RSAKeyPairResult>, data: Buffer) {
    return Object.entries(serviceKeys)
        .map(([name, key]) => ({
            service: name,
            key: bruteForceRSADecrypt(data, key.privateKey)
        })).find(service => !!service.key);
}