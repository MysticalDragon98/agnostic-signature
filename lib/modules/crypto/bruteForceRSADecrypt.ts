import { rsaDecrypt } from "./rsaDecrypt";

export default function bruteForceRSADecrypt (data: Buffer, privateKeyPem: string) {
    for (let i=0;i<256;i++) {
        try {
            const decryptedData = rsaDecrypt(Buffer.concat([Buffer.from([i]), data]), privateKeyPem);
            return decryptedData;
        } catch (e) {
            //console.log(e)
            if (e.code !== 'ERR_OSSL_RSA_OAEP_DECODING_ERROR') continue;
        }
    }
}