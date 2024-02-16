/// <reference types="node" />
import { Buffer } from "node:buffer";
export declare class SafeToken {
    token: string;
    refreshT: number;
    tokenT: number;
    refreshtoken: string;
    lastrefreshTime: number;
    lastAccessTime: number;
    rtStoreKey: string;
    key: string;
    iv: Buffer;
    constructor(init?: {
        timeWindow?: number;
        rtDays?: number;
        encryptionKey?: string;
        rtStoreKey?: string;
    });
    newAccessToken(data?: string, _r?: true): string;
    newRefreshToken(data?: string, _r?: true): string;
    verifyAccessToken(hashString: string, _r?: boolean): string | boolean;
    verifyRefreshToken(hashString: string): string | boolean;
    resetAccessToken(): void;
    resetRefreshToken(): void;
    static timeDiff(timestamp: number): {
        day: number;
        ms: number;
    };
    static create(): string;
    static retrToken(rtStoreKey: string): [number, Buffer, string];
    private dec;
    private enc;
}
