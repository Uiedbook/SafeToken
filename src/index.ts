export class SafeToken {
  token: string;
  refreshT: number;
  tokenT: number;
  refreshtoken: string;
  lastrefreshTime: number;
  lastAccessTime: number;
  constructor(init?: { TokenTime?: number; RefreshDays: number }) {
    this.token = SafeToken.createToken();
    this.refreshtoken = SafeToken.createToken();
    this.tokenT = init?.TokenTime || 3600;
    this.refreshT = init?.RefreshDays || 30;
    this.lastrefreshTime = Date.now();
    this.lastAccessTime = Date.now();
  }
  newToken(_r?: true) {
    let si = Math.floor(
      Math.random() *
        ((_r ? this.refreshtoken.length : this.token.length) - 10 + 1)
    );
    if (String(si).length < 2) {
      si = (si || 1) * 10;
    }
    if (si > this.token.length - 15) {
      si = si - 77;
    }
    setTimeout(() => {
      const diff = SafeToken.timeDiff(this.lastAccessTime);
      if (diff.diffSeconds > this.tokenT) {
        this.resetAccessToken();
      }
      this.token = SafeToken.createToken();
    });
    return (_r ? this.refreshtoken : this.token).slice(si - 10, si) + "@" + si;
  }
  verifyToken(hashString: string, _r?: true): boolean {
    const [hash, si] = hashString.split("@");
    const key = (_r ? this.refreshtoken : this.token).slice(
      Number(si) - 10,
      Number(si)
    );
    return key === hash;
  }
  verifyRefreshToken(hashString: string): boolean {
    return this.verifyToken(hashString, true);
  }

  getRefreshToken() {
    const diff = SafeToken.timeDiff(this.lastrefreshTime);
    if (diff.day > this.refreshT) {
      this.resetRefreshToken();
    }
    return this.newToken(true);
  }
  resetAccessToken() {
    this.token = SafeToken.createToken();
    this.lastAccessTime = Date.now();
  }
  resetRefreshToken() {
    this.refreshtoken = SafeToken.createToken();
    this.lastrefreshTime = Date.now();
  }
  static timeDiff(timestamp: number) {
    const diffSeconds = Math.floor(
      Math.abs(new Date(Date.now()).getTime() - new Date(timestamp).getTime()) /
        1000
    );
    return {
      day: Math.floor(diffSeconds / 86400) % 30,
      diffSeconds,
    };
  }
  static createToken() {
    const chars =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    const charsLength = chars.length;
    let length = Math.max(Math.random() * 1000, 99);
    let uuid = "";
    while (uuid.length < length) {
      const randomIndex = Math.floor(Math.random() * charsLength);
      uuid += chars.charAt(randomIndex);
    }
    return uuid;
  }
}
