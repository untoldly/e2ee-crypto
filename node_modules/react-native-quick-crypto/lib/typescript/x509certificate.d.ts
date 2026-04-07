import { Buffer } from '@craftzdog/react-native-buffer';
import { PublicKeyObject, KeyObject } from './keys';
import type { BinaryLike } from './utils';
export interface X509LegacyObject {
    subject: string;
    issuer: string;
    subjectaltname: string;
    infoAccess: string;
    ca: boolean;
    modulus: undefined;
    bits: undefined;
    exponent: undefined;
    valid_from: string;
    valid_to: string;
    fingerprint: string;
    fingerprint256: string;
    fingerprint512: string;
    ext_key_usage: string[];
    serialNumber: string;
    raw: Buffer;
}
export interface CheckOptions {
    subject?: 'default' | 'always' | 'never';
    wildcards?: boolean;
    partialWildcards?: boolean;
    multiLabelWildcards?: boolean;
    singleLabelSubdomains?: boolean;
}
export declare class X509Certificate {
    private readonly handle;
    private readonly cache;
    constructor(buffer: BinaryLike);
    private cached;
    get subject(): string;
    get subjectAltName(): string;
    get issuer(): string;
    get infoAccess(): string;
    get validFrom(): string;
    get validTo(): string;
    get validFromDate(): Date;
    get validToDate(): Date;
    get fingerprint(): string;
    get fingerprint256(): string;
    get fingerprint512(): string;
    get extKeyUsage(): string[];
    get keyUsage(): string[];
    get serialNumber(): string;
    get signatureAlgorithm(): string;
    get signatureAlgorithmOid(): string;
    get ca(): boolean;
    get raw(): Buffer;
    get publicKey(): PublicKeyObject;
    get issuerCertificate(): undefined;
    checkHost(name: string, options?: CheckOptions): string | undefined;
    checkEmail(email: string, options?: CheckOptions): string | undefined;
    checkIP(ip: string): string | undefined;
    checkIssued(otherCert: X509Certificate): boolean;
    checkPrivateKey(pkey: KeyObject): boolean;
    verify(pkey: KeyObject): boolean;
    toString(): string;
    toJSON(): string;
    toLegacyObject(): X509LegacyObject;
}
//# sourceMappingURL=x509certificate.d.ts.map