export declare class SafeToken {
    private refreshTime;
    private accessTime;
    private key;
    private salt;
    constructor(init: {
        timeWindow?: number;
        rtDays?: number;
        encryptionKey: string;
    });
    newAccessToken(data?: string): string;
    newRefreshToken(data: string): string;
    verifyAccessToken(hash: string): string | boolean;
    verifyRefreshToken(hash: string): false | undefined;
}
