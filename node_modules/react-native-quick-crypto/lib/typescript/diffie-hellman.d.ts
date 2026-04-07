import { Buffer } from '@craftzdog/react-native-buffer';
export declare class DiffieHellman {
    private _hybrid;
    constructor(sizeOrPrime: number | Buffer | string, generator?: number | Buffer | string, encoding?: BufferEncoding);
    generateKeys(encoding?: BufferEncoding): Buffer | string;
    computeSecret(otherPublicKey: Buffer | string, inputEncoding?: BufferEncoding, outputEncoding?: BufferEncoding): Buffer | string;
    getPrime(encoding?: BufferEncoding): Buffer | string;
    getGenerator(encoding?: BufferEncoding): Buffer | string;
    getPublicKey(encoding?: BufferEncoding): Buffer | string;
    getPrivateKey(encoding?: BufferEncoding): Buffer | string;
    setPublicKey(publicKey: Buffer | string, encoding?: BufferEncoding): void;
    setPrivateKey(privateKey: Buffer | string, encoding?: BufferEncoding): void;
    get verifyError(): number;
}
export declare function createDiffieHellman(primeOrSize: number | string | Buffer, primeEncodingOrGenerator?: string | number | Buffer, generator?: number | string | Buffer, _generatorEncoding?: string): DiffieHellman;
export declare function getDiffieHellman(groupName: string): DiffieHellman;
export { getDiffieHellman as createDiffieHellmanGroup };
//# sourceMappingURL=diffie-hellman.d.ts.map