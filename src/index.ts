import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";

export class SafeToken {
  token: string;
  refreshT: number;
  tokenT: number;
  refreshtoken: string;
  lastrefreshTime: number;
  lastAccessTime: number;
  rtStoreKey?: string;
  key: string;
  iv = randomBytes(16);
  constructor(init?: {
    timeWindow?: number;
    rtDays?: number;
    encryptionKey?: string;
    rtStoreKey?: string;
  }) {
    this.token = SafeToken.create();
    this.tokenT = init?.timeWindow || 3600;
    this.refreshT = init?.rtDays || 30;
    this.lastAccessTime = Date.now();
    this.rtStoreKey = init?.rtStoreKey;
    this.key =
      typeof init?.encryptionKey === "string" &&
      init.encryptionKey.length === 32
        ? init.encryptionKey
        : "";
    if (typeof init?.rtStoreKey === "string") {
      [this.lastrefreshTime, this.refreshtoken] = SafeToken.retrToken(
        init.rtStoreKey
      );
    } else {
      this.refreshtoken = SafeToken.create();
      this.lastrefreshTime = Date.now();
    }
  }
  newAccessToken(data: string = "", _r?: true) {
    if (data) {
      if (typeof data !== "string")
        throw new Error("data to encrypt is invalid!, must be string type");
      data = this.enc(data);
    }
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
      this.token = SafeToken.create();
    });

    return (
      si +
      ":" +
      (data + (_r ? this.refreshtoken : this.token).slice(si - 10, si))
    );
  }
  newRefreshToken(data: string = "", _r?: true) {
    const diff = SafeToken.timeDiff(this.lastrefreshTime);
    if (diff.day > this.refreshT) {
      this.resetRefreshToken();
    }
    return this.newAccessToken(data, true);
  }
  verifyToken(hashString: string, _r?: true): string | boolean {
    let data = true;
    let [si, hash] = (hashString || "").split(":");
    if (!si || !hash) return false; //? fixed
    if (hash.length !== 10) {
      data = this.dec(hash.slice(0, hash.length - 10)) as unknown as boolean;
      hash = hash.slice(hash.length - 10, hash.length);
    }
    const key = (_r ? this.refreshtoken : this.token).slice(
      Number(si) - 10,
      Number(si)
    );
    return key === hash && data;
  }
  verifyRefreshToken(hashString: string) {
    return this.verifyToken(hashString, true);
  }
  resetAccessToken() {
    this.token = SafeToken.create();
    this.lastAccessTime = Date.now();
  }
  resetRefreshToken() {
    this.refreshtoken = SafeToken.create();
    if (typeof this.rtStoreKey === "string") {
      writeFile(
        this.rtStoreKey || "_refresh_token",
        this.refreshT + ":" + this.refreshtoken
      );
    }
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
  static create() {
    // 500 =  1k(min), 1000 = 2k(max) gen string length
    return randomBytes(Math.max(Math.random() * 999, 499)).toString("hex");
  }
  static retrToken(rtStoreKey: string): [number, string] {
    try {
      const data = readFileSync(rtStoreKey || "_refresh_token", {
        encoding: "utf8",
      });
      if (!data) {
        return [Date.now(), SafeToken.create()];
      } else {
        const [date, lastStoredToken] = data.split(":");
        return [Number(date), lastStoredToken];
      }
    } catch (error) {
      return [Date.now(), SafeToken.create()];
    }
  }
  private dec(text: string) {
    if (!this.key)
      throw new Error("Encryption key is invalid!, must be 32 charaters");
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
  }
  private enc(text: string) {
    if (!this.key)
      throw new Error("Encryption key is invalid!, must be 32 charaters");
    const cipher = createCipheriv(
      "aes-256-cbc",
      Buffer.from(this.key),
      this.iv
    );
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return encrypted.toString("hex");
  }
}
