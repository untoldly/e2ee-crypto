import { Buffer } from '@craftzdog/react-native-buffer';
import type { BinaryLike } from './utils';
export interface GeneratePrimeOptions {
    safe?: boolean;
    bigint?: boolean;
    add?: ArrayBuffer | Buffer | Uint8Array;
    rem?: ArrayBuffer | Buffer | Uint8Array;
}
export interface CheckPrimeOptions {
    checks?: number;
}
export declare function generatePrimeSync(size: number, options?: GeneratePrimeOptions): Buffer | bigint;
type GeneratePrimeCallback = (err: Error | null, prime: Buffer | bigint) => void;
export declare function generatePrime(size: number, options: GeneratePrimeOptions | GeneratePrimeCallback, callback?: GeneratePrimeCallback): void;
export declare function checkPrimeSync(candidate: BinaryLike | bigint, options?: CheckPrimeOptions): boolean;
type CheckPrimeCallback = (err: Error | null, result: boolean) => void;
export declare function checkPrime(candidate: BinaryLike | bigint, options: CheckPrimeOptions | CheckPrimeCallback, callback?: CheckPrimeCallback): void;
export {};
//# sourceMappingURL=prime.d.ts.map