import { Buffer } from '@craftzdog/react-native-buffer';
export declare class ECDH {
    private static _convertKeyHybrid;
    private static get convertKeyHybrid();
    private _hybrid;
    constructor(curveName: string);
    generateKeys(): Buffer;
    computeSecret(otherPublicKey: Buffer | string | {
        code: number;
        byteLength: number;
    }, inputEncoding?: BufferEncoding): Buffer;
    getPrivateKey(): Buffer;
    setPrivateKey(privateKey: Buffer | string, encoding?: BufferEncoding): void;
    getPublicKey(encoding?: BufferEncoding): Buffer | string;
    setPublicKey(publicKey: Buffer | string, encoding?: BufferEncoding): void;
    static convertKey(key: Buffer | string, curve: string, inputEncoding?: BufferEncoding, outputEncoding?: BufferEncoding, format?: 'uncompressed' | 'compressed' | 'hybrid'): Buffer | string;
}
export declare function createECDH(curveName: string): ECDH;
//# sourceMappingURL=ecdh.d.ts.map