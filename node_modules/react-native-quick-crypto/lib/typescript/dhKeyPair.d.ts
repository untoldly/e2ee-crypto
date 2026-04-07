import { Buffer } from '@craftzdog/react-native-buffer';
import { PublicKeyObject, PrivateKeyObject } from './keys/classes';
import type { DhKeyPair } from './specs/dhKeyPair.nitro';
import type { GenerateKeyPairOptions, KeyPairGenConfig } from './utils/types';
export declare class DhKeyPairGen {
    native: DhKeyPair;
    constructor(options: GenerateKeyPairOptions);
    generateKeyPair(): Promise<void>;
    generateKeyPairSync(): void;
}
export declare function dh_generateKeyPairNode(options: GenerateKeyPairOptions | undefined, encoding: KeyPairGenConfig): Promise<{
    publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
    privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
}>;
export declare function dh_generateKeyPairNodeSync(options: GenerateKeyPairOptions | undefined, encoding: KeyPairGenConfig): {
    publicKey: PublicKeyObject | Buffer | string | ArrayBuffer;
    privateKey: PrivateKeyObject | Buffer | string | ArrayBuffer;
};
//# sourceMappingURL=dhKeyPair.d.ts.map