import { readFileSync, writeFileSync } from "node:fs";
import pkg1 from "tweetnacl";
import pkg2 from "tweetnacl-util";
const { secretbox, randomBytes } = pkg1;
const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = pkg2;

export class SafeToken {
  token: string;
  refreshT: number;
  tokenT: number;
  refreshtoken: string;
  lastrefreshTime: number;
  lastAccessTime: number;
  rtStoreKey: string = "_refresh_token";
  key: string;
  constructor(init?: {
    timeWindow?: number;
    rtDays?: number;
    encryptionKey?: string;
    rtStoreKey?: string;
  }) {
    // ? reset access tokens
    this.token = SafeToken.create();
    this.lastAccessTime = Date.now();
    // ? time window setup
    this.tokenT = init?.timeWindow || 3600_000;
    this.refreshT = init?.rtDays || 29;
    // ? refresh file name
    this.rtStoreKey = init?.rtStoreKey || "_refresh_token";
    //? setup encryption keys
    this.key =
      typeof init?.encryptionKey === "string" &&
      init.encryptionKey.length === 32
        ? init.encryptionKey
        : "";
    // ? retrieve last refresh tokens
    [this.lastrefreshTime, this.refreshtoken] = SafeToken.retrToken(
      this.rtStoreKey
    );
  }
  newAccessToken(data: string = "", _r?: true): string {
    if (data) {
      if (typeof data !== "string")
        throw new Error("Data to encrypt must be string type");
      data = this.enc(data);
    }
    //? create token
    let si = Math.floor(
      Math.random() *
        ((_r ? this.refreshtoken.length : this.token.length) - 10 + 1)
    );
    if (String(si).length < 2) {
      si = (si || 1) * 10;
    }
    if (_r && si > this.refreshtoken.length - 15) {
      si = si - 77;
    }
    if (!_r && si > this.token.length - 15) {
      si = si - 77;
    }

    return (
      si +
      ":" +
      (data + (_r ? this.refreshtoken : this.token).slice(si - 10, si))
    );
  }
  newRefreshToken(data: string = "", _r?: true): string {
    return this.newAccessToken(data, true);
  }
  verifyAccessToken(hashString: string, _r = false): string | boolean {
    if (!_r) {
      const diff = SafeToken.timeDiff(this.lastAccessTime);
      if (diff.ms > this.tokenT) {
        this.resetAccessToken();
      }
    }
    let data = true;
    let [si, hash] = (hashString || "").split(":");
    if (!si || !hash) return false; //? fixed
    if (hash.length !== 10) {
      [hash, data as unknown as string] = [
        hash.slice(hash.length - 10, hash.length),
        this.dec(hash.slice(0, hash.length - 10)),
      ];
    }
    const key = (_r ? this.refreshtoken : this.token).slice(
      Number(si) - 10,
      Number(si)
    );
    return key === hash && data;
  }
  verifyRefreshToken(hashString: string) {
    const diff = SafeToken.timeDiff(this.lastrefreshTime);
    if (diff.day > this.refreshT) {
      this.resetRefreshToken();
    }
    return this.verifyAccessToken(hashString, true);
  }
  resetAccessToken() {
    this.token = SafeToken.create();
    this.lastAccessTime = Date.now();
  }
  resetRefreshToken() {
    this.refreshtoken = SafeToken.create();
    this.lastrefreshTime = Date.now();
    writeFileSync(
      this.rtStoreKey,
      this.lastrefreshTime + ":" + ":" + this.refreshtoken
    );
  }
  static timeDiff(timestamp: number) {
    const ms = Math.floor(
      Math.abs(new Date(Date.now()).getTime() - new Date(timestamp).getTime())
    );
    return {
      day: Math.round(ms / 86400_000),
      ms,
    };
  }
  static create() {
    // 500 =  1k(min), 1000 = 2k(max) gen string length
    return randomBytes(Math.max(Math.random() * 999, 499)).toString();
  }
  static retrToken(rtStoreKey: string): [number, string] {
    let rt: [number, string] = [Date.now(), SafeToken.create()];
    try {
      const data = readFileSync(rtStoreKey, {
        encoding: "utf8",
      });
      if (data) {
        const [date, iv, lastStoredToken] = data.split(":");
        rt = [Number(date), lastStoredToken];
      }
    } catch (error) {
      writeFileSync(rtStoreKey, rt[0] + ":" + rt[1]);
    }

    return rt;
  }
  private dec(msg: string) {
    const ku8arr = decodeBase64(this.key);
    const msgu8 = decodeBase64(msg);
    const nonce = msgu8.slice(0, secretbox.nonceLength);
    const message = msgu8.slice(secretbox.nonceLength, msg.length);
    const decrypted = secretbox.open(message, nonce, ku8arr);
    if (!decrypted) {
      throw new Error("Could not decrypt message");
    }
    const base64DecryptedMessage = encodeUTF8(decrypted);
    return JSON.parse(base64DecryptedMessage);
  }
  private enc(msg: string) {
    const ku8arr = decodeBase64(this.key);
    const nonce = randomBytes(secretbox.nonceLength);
    const msgu8 = decodeUTF8(msg);
    const box = secretbox(msgu8, nonce, ku8arr);
    const fm = new Uint8Array(nonce.length + box.length);
    fm.set(nonce);
    fm.set(box, nonce.length);
    const base64fm = encodeBase64(fm);
    return base64fm;
  }
}
export const generateKey = () => encodeBase64(randomBytes(secretbox.keyLength));
