import { Buffer } from '@craftzdog/react-native-buffer';
import type { BinaryLike } from './utils';
export interface Argon2Params {
    message: BinaryLike;
    nonce: BinaryLike;
    parallelism: number;
    tagLength: number;
    memory: number;
    passes: number;
    secret?: BinaryLike;
    associatedData?: BinaryLike;
    version?: number;
}
export declare function argon2Sync(algorithm: string, params: Argon2Params): Buffer;
export declare function argon2(algorithm: string, params: Argon2Params, callback: (err: Error | null, result: Buffer) => void): void;
//# sourceMappingURL=argon2.d.ts.map