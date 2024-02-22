import CryptoJS from "crypto-js";

export class SafeToken {
  // ? full token
  private refreshTime: number;
  private accessTime: number;
  private key: string;
  constructor(init: {
    timeWindow: number;
    rtDays: number;
    encryptionKey: string;
  }) {
    // ? time window setup
    this.accessTime = init?.timeWindow || 3600_000;
    this.refreshTime = init?.rtDays || 29;
    //? setup encryption keys
    this.key = init.encryptionKey;
  }
  newAccessToken(data: string = ""): string {
    if (data) {
      if (typeof data !== "string")
        throw new Error("Data to encrypt must be string type");
    }
    return (
      SafeToken.encode_timestamp() +
      CryptoJS.AES.encrypt(data, this.key).toString()
    );
  }
  newRefreshToken(data: string): string {
    return this.newAccessToken(data);
  }
  verifyAccessToken(hash: string): string | boolean {
    const [time, token] = [hash.slice(0, 8), hash.slice(8)];
    if (!SafeToken.IsIntime(this.accessTime, time)) {
      return false;
    }
    return CryptoJS.AES.decrypt(token, this.key).toString(CryptoJS.enc.Utf8);
  }
  verifyRefreshToken(hash: string) {
    const [time, token] = [hash.slice(0, 8), hash.slice(8)];
    if (!SafeToken.IsIntime(this.refreshTime, time, true)) {
      return false;
    }
    return CryptoJS.AES.decrypt(token, this.key).toString(CryptoJS.enc.Utf8);
  }
  static IsIntime(number: number, lastTime: string, r?: boolean): boolean {
    const ms = Math.floor(
      Math.abs(
        new Date(Date.now()).getTime() -
          new Date(parseInt(lastTime, 16) * 1000).getTime()
      )
    );
    if (r) {
      if (number > Math.round(ms / 86400_000)) {
        return true;
      } else {
        return false;
      }
    } else {
      if (number > ms) {
        return true;
      } else {
        return false;
      }
    }
  }
  static encode_timestamp(): string {
    const time = ~~(new Date().getTime() / 1000);
    const buffer = Buffer.alloc(4);
    // 4-byte timestamp
    buffer[3] = time & 0xff;
    buffer[2] = (time >> 8) & 0xff;
    buffer[1] = (time >> 16) & 0xff;
    buffer[0] = (time >> 24) & 0xff;
    return buffer.toString("hex");
  }
}
