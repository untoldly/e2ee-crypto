import type { EcKeyPair } from './specs/ecKeyPair.nitro';
import { CryptoKey, PublicKeyObject, PrivateKeyObject } from './keys/classes';
import type { CryptoKeyPair, KeyPairOptions, KeyUsage, SubtleAlgorithm, BufferLike, BinaryLike, JWK, ImportFormat, GenerateKeyPairOptions, KeyPairGenConfig } from './utils/types';
import { Buffer } from '@craftzdog/react-native-buffer';
export declare function getCurves(): string[];
export declare class Ec {
    native: EcKeyPair;
    constructor(curve: string);
    generateKeyPair(): Promise<CryptoKeyPair>;
    generateKeyPairSync(): CryptoKeyPair;
}
export declare function ecImportKey(format: ImportFormat, keyData: BufferLike | BinaryLike | JWK, algorithm: SubtleAlgorithm, extractable: boolean, keyUsages: KeyUsage[]): CryptoKey;
export declare const ecdsaSignVerify: (key: CryptoKey, data: BufferLike, { hash }: SubtleAlgorithm, signature?: BufferLike) => ArrayBuffer | boolean;
export declare function ec_generateKeyPair(name: string, namedCurve: string, extractable: boolean, keyUsages: KeyUsage[], _options?: KeyPairOptions): Promise<CryptoKeyPair>;
export declare function ec_generateKeyPairNode(options: GenerateKeyPairOptions | undefined, encoding: KeyPairGenConfig): Promise<{
    publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
    privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}>;
export declare function ec_generateKeyPairNodeSync(options: GenerateKeyPairOptions | undefined, encoding: KeyPairGenConfig): {
    publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
    privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
};
export declare function ecDeriveBits(algorithm: SubtleAlgorithm, baseKey: CryptoKey, length: number | null): ArrayBuffer;
//# sourceMappingURL=ec.d.ts.map