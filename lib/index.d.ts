declare class SafeToken {
    token: string;
    refreshT: number;
    tokenT: number;
    refreshtoken: string;
    lastrefreshTime: number;
    lastAccessTime: number;
    constructor(init?: {
        TokenTime?: number;
        RefreshDays: number;
    });
    newToken(_r?: true): string;
    verifyToken(hashString: string, _r?: true): boolean;
    verifyRefreshToken(hashString: string): boolean;
    getRefreshToken(): string;
    resetAccessToken(): void;
    resetRefreshToken(): void;
    static timeDiff(timestamp: number): {
        day: number;
        diffSeconds: number;
    };
    static createToken(): string;
}

export { SafeToken };
