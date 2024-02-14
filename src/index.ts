import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import { readFileSync, writeFileSync } from "node:fs";

export class SafeToken {
  token: string;
  refreshT: number;
  tokenT: number;
  refreshtoken: string;
  lastrefreshTime: number;
  lastAccessTime: number;
  rtStoreKey: string = "_refresh_token";
  key: string;
  iv = randomBytes(16);
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
    this.refreshT = init?.rtDays || 30;
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
    // ? invalidate old tokens
    if (!_r) {
      const diff = SafeToken.timeDiff(this.lastAccessTime);
      if (diff.diffSeconds > this.tokenT) {
        this.resetAccessToken();
      }
    }
    //? create token
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

    return (
      si +
      ":" +
      (data + (_r ? this.refreshtoken : this.token).slice(si - 10, si))
    );
  }
  newRefreshToken(data: string = "", _r?: true): string {
    const diff = SafeToken.timeDiff(this.lastrefreshTime);
    if (diff.day > this.refreshT) {
      this.resetRefreshToken();
    }
    return this.newAccessToken(data, true);
  }
  verifyAccessToken(hashString: string, _r = false): string | boolean {
    let data = true;
    let [si, hash] = (hashString || "").split(":");
    if (!si || !hash) return false; //? fixed
    if (hash.length !== 10) {
      [hash, data] = [
        hash.slice(hash.length - 10, hash.length),
        this.dec(hash.slice(0, hash.length - 10)),
      ];
      // hash = hash.slice(hash.length - 10, hash.length);
    }
    const key = (_r ? this.refreshtoken : this.token).slice(
      Number(si) - 10,
      Number(si)
    );
    // if (key !== hash) {
    //   console.log("Boohoo ==>", {
    //     key,
    //     hash,
    //     _r,
    //     data,
    //     si,
    //     len: this.token.length,
    //   });
    // }
    return key === hash && data;
  }
  verifyRefreshToken(hashString: string) {
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
      this.lastrefreshTime + ":" + this.refreshtoken
    );
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
  static create() {
    // 500 =  1k(min), 1000 = 2k(max) gen string length
    return randomBytes(Math.max(Math.random() * 999, 499)).toString("hex");
  }
  static retrToken(rtStoreKey: string): [number, string] {
    let rt: [number, string] = [Date.now(), SafeToken.create()];
    try {
      const data = readFileSync(rtStoreKey, {
        encoding: "utf8",
      });
      if (data) {
        const [date, lastStoredToken] = data.split(":");
        rt = [Number(date), lastStoredToken];
      }
    } catch (error) {
      writeFileSync(rtStoreKey, rt[0] + ":" + rt[1]);
    }
    return rt;
  }
  private dec(text: string) {
    if (!this.key) throw new Error("Encryption key must be 32 charaters");
    const decipher = createDecipheriv(
      "aes-256-cbc",
      Buffer.from(this.key),
      this.iv
    );
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(text, "hex")),
      decipher.final(),
    ]);
    return decrypted.toString();
    // text = Buffer.from(text, "hex").toString("binary");
    // const decipher = createDecipheriv("aes-256-cbc", this.key, this.iv);
    // let decoded = decipher.update(text, "binary", "utf8");
    // decoded += decipher.final("utf8");
    // return decoded;
  }
  private enc(text: string) {
    if (!this.key) throw new Error("Encryption key must be 32 charaters");
    const cipher = createCipheriv(
      "aes-256-cbc",
      Buffer.from(this.key),
      this.iv
    );
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return encrypted.toString("hex");
    // const encipher = createCipheriv("aes-256-cbc", this.key, this.iv);
    // let encryptdata = encipher.update(text, "utf8", "binary");
    // encryptdata += encipher.final("binary");
    // return Buffer.from(encryptdata, "binary").toString("hex");
  }
}
