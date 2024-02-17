export declare class SafeToken {
    private FA_token;
    private FR_token;
    private refreshTime;
    private accessTime;
    private lastrefreshTime;
    private lastAccessTime;
    private rtStoreKey;
    private key;
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
    static retrToken(rtStoreKey: string): [number, string];
    private dec;
    private enc;
}
export declare const generateKey: () => string;
