//* Imports

import generateServicesKeys from "./lib/modules/services/generateServicesKeys";
import { generateRSAKeyPair } from "./lib/modules/crypto/generateRSAKeypair";
import { signData } from "./lib/modules/crypto/signData";
import { rsaEncrypt } from "./lib/modules/crypto/rsaEncrypt";
import { rsaDecrypt } from "./lib/modules/crypto/rsaDecrypt";
import bruteForceRSADecrypt from "./lib/modules/crypto/bruteForceRSADecrypt";
import { extractSignatureAndData } from "./lib/modules/crypto/extractSignatureAndData";
import findCorrespondingServiceKey from "./lib/modules/crypto/findCorrespondingServiceKey";
import { verifySignature } from "./lib/modules/crypto/verifySignature";

async function main () {
    //* Backend generates temporal keys per service
    const keys = await generateServicesKeys(['bancolombia', 'bbva', 'nequi']);
    //* Client has its auto generated key
    const clientWallet = await generateRSAKeyPair();
    const service = 'nequi';
    const message = {
        publicKey: clientWallet.publicKey,
        data: {
            username: 'camilotd',
            password: '123456',
            nit: '78345684587534975'
        }
    };

    //* Client signs the data so it can be verified later
    const signature = signData(Buffer.from(JSON.stringify(message.data)), clientWallet.privateKey);
    //* Client encrypts the data using the provided PUBLIC keys for the service he wants to interact
    const data = rsaEncrypt(signature, keys[service].publicKey);

    //* Backend side
    const decryptedData = findCorrespondingServiceKey(keys, data);
    const verified = verifySignature(decryptedData.key, message.publicKey);

    if (!verified) {
        console.log("Unauthorized user.");
    } else {
        const signatureData = extractSignatureAndData(decryptedData.key);

        console.log("Service Key:", decryptedData.service);
        console.log("Message:", JSON.parse(signatureData.data.toString()));
    }
}

main();

process.on('uncaughtException', console.log);
process.on('unhandledRejection', console.log);