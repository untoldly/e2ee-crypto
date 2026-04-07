import type { MlKemKeyPair } from './specs/mlKemKeyPair.nitro';
import { CryptoKey, KeyObject } from './keys';
import type { CryptoKeyPair, KeyUsage, EncapsulateResult, BinaryLike } from './utils';
export type MlKemVariant = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
type KeyInput = BinaryLike | KeyObject | CryptoKey | KeyInputObject;
export interface KeyInputObject {
    key: BinaryLike | KeyObject | CryptoKey;
    format?: 'pem' | 'der';
    type?: 'pkcs1' | 'pkcs8' | 'spki' | 'sec1';
}
export declare class MlKem {
    variant: MlKemVariant;
    native: MlKemKeyPair;
    constructor(variant: MlKemVariant);
    generateKeyPair(): Promise<void>;
    generateKeyPairSync(): void;
    getPublicKey(): ArrayBuffer;
    getPrivateKey(): ArrayBuffer;
    setPublicKey(keyData: ArrayBuffer, format: number, type: number): void;
    setPrivateKey(keyData: ArrayBuffer, format: number, type: number): void;
    encapsulate(): Promise<EncapsulateResult>;
    encapsulateSync(): EncapsulateResult;
    decapsulate(ciphertext: ArrayBuffer): Promise<ArrayBuffer>;
    decapsulateSync(ciphertext: ArrayBuffer): ArrayBuffer;
}
export declare function encapsulate(key: KeyInput, callback?: (err: Error | null, result?: EncapsulateResult) => void): EncapsulateResult | void;
export declare function decapsulate(key: KeyInput, ciphertext: BinaryLike, callback?: (err: Error | null, result?: ArrayBuffer) => void): ArrayBuffer | void;
export declare function mlkem_generateKeyPairWebCrypto(variant: MlKemVariant, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair>;
export {};
//# sourceMappingURL=mlkem.d.ts.map