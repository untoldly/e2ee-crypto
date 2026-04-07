import { Buffer } from '@craftzdog/react-native-buffer';
import type { BinaryLike } from './utils';
export declare class Certificate {
    static exportChallenge(spkac: BinaryLike, encoding?: BufferEncoding): Buffer;
    static exportPublicKey(spkac: BinaryLike, encoding?: BufferEncoding): Buffer;
    static verifySpkac(spkac: BinaryLike, encoding?: BufferEncoding): boolean;
}
//# sourceMappingURL=certificate.d.ts.map