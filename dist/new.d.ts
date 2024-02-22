export declare class SafeToken {
    private refreshTime;
    private accessTime;
    private key;
    constructor(init: {
        timeWindow: number;
        rtDays: number;
        encryptionKey: string;
    });
    newAccessToken(data?: string): string;
    newRefreshToken(data: string): string;
    verifyAccessToken(hash: string): string | boolean;
    verifyRefreshToken(hash: string): any;
    static IsIntime(number: number, lastTime: string, r?: boolean): boolean;
    static encode_timestamp(): string;
}
