import { readFileSync, writeFileSync } from "node:fs";
import pkg1 from "tweetnacl";
import pkg2 from "tweetnacl-util";
const { secretbox, randomBytes } = pkg1;
const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = pkg2;
export class SafeToken {
    // ? full token
    FA_token;
    FR_token;
    refreshTime;
    accessTime;
    // ? access time
    lastrefreshTime;
    lastAccessTime;
    // ? FR key
    rtStoreKey = "_safetoken";
    key;
    constructor(init) {
        // ? reset access tokens
        this.FA_token = SafeToken.create();
        this.lastAccessTime = Date.now();
        // ? time window setup
        this.accessTime = init?.timeWindow || 3600_000;
        this.refreshTime = init?.rtDays || 29;
        // ? refresh file name
        if (init?.rtStoreKey)
            this.rtStoreKey = init.rtStoreKey;
        //? setup encryption keys
        this.key = init?.encryptionKey || "";
        // ? retrieve last refresh tokens
        [this.lastrefreshTime, this.FR_token] = SafeToken.retrToken(this.rtStoreKey);
    }
    newAccessToken(data = "", _r) {
        if (data) {
            if (typeof data !== "string")
                throw new Error("Data to encrypt must be string type");
            data = this.enc(data);
        }
        //? create token
        let si = Math.floor(Math.random() *
            ((_r ? this.FR_token.length : this.FA_token.length) - 10 + 1));
        if (String(si).length < 2) {
            si = (si || 1) * 10;
        }
        if (_r && si > this.FR_token.length - 15) {
            si = si - 77;
        }
        if (!_r && si > this.FA_token.length - 15) {
            si = si - 77;
        }
        return (si +
            ":" +
            (data + (_r ? this.FR_token : this.FA_token).slice(si - 10, si)));
    }
    newRefreshToken(data = "", _r) {
        return this.newAccessToken(data, true);
    }
    verifyAccessToken(hashString, _r = false) {
        if (!_r) {
            const diff = SafeToken.timeDiff(this.lastAccessTime);
            if (diff.ms > this.accessTime) {
                this.resetAccessToken();
            }
        }
        let data = true;
        let [si, hash] = (hashString || "").split(":");
        if (!si || !hash)
            return false; //? fixed
        if (hash.length !== 10) {
            [hash, data] = [
                hash.slice(hash.length - 10, hash.length),
                this.dec(hash.slice(0, hash.length - 10)),
            ];
        }
        const key = (_r ? this.FR_token : this.FA_token).slice(Number(si) - 10, Number(si));
        return key === hash && data;
    }
    verifyRefreshToken(hashString) {
        const diff = SafeToken.timeDiff(this.lastrefreshTime);
        if (diff.day > this.refreshTime) {
            this.resetRefreshToken();
        }
        return this.verifyAccessToken(hashString, true);
    }
    resetAccessToken() {
        this.FA_token = SafeToken.create();
        this.lastAccessTime = Date.now();
    }
    resetRefreshToken() {
        this.FR_token = SafeToken.create();
        this.lastrefreshTime = Date.now();
        writeFileSync(this.rtStoreKey, this.lastrefreshTime + ":" + ":" + this.FR_token);
    }
    static timeDiff(timestamp) {
        const ms = Math.floor(Math.abs(new Date(Date.now()).getTime() - new Date(timestamp).getTime()));
        return {
            day: Math.round(ms / 86400_000),
            ms,
        };
    }
    static create() {
        // 500 =  1k(min), 1000 = 2k(max) gen string length
        return randomBytes(Math.max(Math.random() * 999, 499)).toString();
    }
    static retrToken(rtStoreKey) {
        let rt = [Date.now(), SafeToken.create()];
        try {
            const data = readFileSync(rtStoreKey, {
                encoding: "utf8",
            });
            if (data) {
                const [date, lastStoredToken] = data.split(":");
                if (data && lastStoredToken) {
                    rt = [Number(date), lastStoredToken];
                }
                else {
                    writeFileSync(rtStoreKey, rt[0] + ":" + rt[1]);
                }
            }
        }
        catch (error) {
            writeFileSync(rtStoreKey, rt[0] + ":" + rt[1]);
        }
        return rt;
    }
    dec(msg) {
        const ku8arr = decodeBase64(this.key);
        const msgu8 = decodeBase64(msg);
        const nonce = msgu8.slice(0, secretbox.nonceLength);
        const message = msgu8.slice(secretbox.nonceLength, msg.length);
        const decrypted = secretbox.open(message, nonce, ku8arr);
        if (!decrypted) {
            throw new Error("Could not decrypt message");
        }
        const base64DecryptedMessage = encodeUTF8(decrypted);
        return base64DecryptedMessage;
    }
    enc(msg) {
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
