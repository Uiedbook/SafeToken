// src/index.ts
import {createCipheriv, createDecipheriv, randomBytes} from "node:crypto";
import {Buffer} from "node:buffer";
import {readFileSync, writeFileSync} from "node:fs";

class SafeToken {
  token;
  refreshT;
  tokenT;
  refreshtoken;
  lastrefreshTime;
  lastAccessTime;
  rtStoreKey = "_refresh_token";
  key;
  iv = randomBytes(16);
  constructor(init) {
    this.token = SafeToken.create();
    this.lastAccessTime = Date.now();
    this.tokenT = init?.timeWindow || 3600000;
    this.refreshT = init?.rtDays || 30;
    this.rtStoreKey = init?.rtStoreKey || "_refresh_token";
    this.key = typeof init?.encryptionKey === "string" && init.encryptionKey.length === 32 ? init.encryptionKey : "";
    [this.lastrefreshTime, this.refreshtoken] = SafeToken.retrToken(this.rtStoreKey);
  }
  newAccessToken(data = "", _r) {
    if (data) {
      if (typeof data !== "string")
        throw new Error("Data to encrypt must be string type");
      data = this.enc(data);
    }
    let si = Math.floor(Math.random() * ((_r ? this.refreshtoken.length : this.token.length) - 10 + 1));
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
    });
    return si + ":" + (data + (_r ? this.refreshtoken : this.token).slice(si - 10, si));
  }
  newRefreshToken(data = "", _r) {
    const diff = SafeToken.timeDiff(this.lastrefreshTime);
    if (diff.day > this.refreshT) {
      this.resetRefreshToken();
    }
    return this.newAccessToken(data, true);
  }
  verifyAccessToken(hashString, _r) {
    let data = true;
    let [si, hash] = (hashString || "").split(":");
    if (!si || !hash)
      return false;
    if (hash.length !== 10) {
      data = this.dec(hash.slice(0, hash.length - 10));
      hash = hash.slice(hash.length - 10, hash.length);
    }
    const key = (_r ? this.refreshtoken : this.token).slice(Number(si) - 10, Number(si));
    return key === hash && data;
  }
  verifyRefreshToken(hashString) {
    return this.verifyAccessToken(hashString, true);
  }
  resetAccessToken() {
    this.token = SafeToken.create();
    this.lastAccessTime = Date.now();
  }
  resetRefreshToken() {
    this.refreshtoken = SafeToken.create();
    this.lastrefreshTime = Date.now();
    writeFileSync(this.rtStoreKey, this.lastrefreshTime + ":" + this.refreshtoken);
  }
  static timeDiff(timestamp) {
    const diffSeconds = Math.floor(Math.abs(new Date(Date.now()).getTime() - new Date(timestamp).getTime()) / 1000);
    return {
      day: Math.floor(diffSeconds / 86400) % 30,
      diffSeconds
    };
  }
  static create() {
    return randomBytes(Math.max(Math.random() * 999, 499)).toString("hex");
  }
  static retrToken(rtStoreKey) {
    let rt = [Date.now(), SafeToken.create()];
    try {
      const data = readFileSync(rtStoreKey, {
        encoding: "utf8"
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
  dec(text) {
    if (!this.key)
      throw new Error("Encryption key must be 32 charaters");
    text = Buffer.from(text, "hex").toString("binary");
    const decipher = createDecipheriv("aes-256-cbc", this.key, this.iv);
    let decoded = decipher.update(text, "binary", "utf8");
    decoded += decipher.final("utf8");
    return decoded;
  }
  enc(text) {
    if (!this.key)
      throw new Error("Encryption key must be 32 charaters");
    const encipher = createCipheriv("aes-256-cbc", this.key, this.iv);
    let encryptdata = encipher.update(text, "utf8", "binary");
    encryptdata += encipher.final("binary");
    return Buffer.from(encryptdata, "binary").toString("hex");
  }
}
export {
  SafeToken
};
