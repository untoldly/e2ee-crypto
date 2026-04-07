import { Buffer } from '@craftzdog/react-native-buffer';
import { PublicKeyObject, PrivateKeyObject } from './keys/classes';
import type { DsaKeyPair } from './specs/dsaKeyPair.nitro';
import type { GenerateKeyPairOptions, KeyPairGenConfig } from './utils/types';
export declare class Dsa {
    native: DsaKeyPair;
    constructor(modulusLength: number, divisorLength?: number);
    generateKeyPair(): Promise<void>;
    generateKeyPairSync(): void;
}
export declare function dsa_generateKeyPairNode(options: GenerateKeyPairOptions | undefined, encoding: KeyPairGenConfig): Promise<{
    publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
    privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}>;
export declare function dsa_generateKeyPairNodeSync(options: GenerateKeyPairOptions | undefined, encoding: KeyPairGenConfig): {
    publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
    privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
};
//# sourceMappingURL=dsa.d.ts.map