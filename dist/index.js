import CryptoJS from "crypto-js";
export class SafeToken {
    // ? full token
    refreshTime;
    accessTime;
    key;
    constructor(init) {
        // ? time window setup
        this.accessTime = init?.timeWindow || 3600_000;
        this.refreshTime = init?.rtDays || 29;
        //? setup encryption keys
        this.key = init.encryptionKey;
    }
    newAccessToken(data = "") {
        if (data) {
            if (typeof data !== "string")
                throw new Error("Data to encrypt must be string type");
        }
        return (SafeToken.encode_timestamp() +
            CryptoJS.AES.encrypt(data, this.key).toString());
    }
    newRefreshToken(data) {
        return this.newAccessToken(data);
    }
    verifyAccessToken(hash) {
        const [time, token] = [hash.slice(0, 8), hash.slice(8)];
        if (!SafeToken.IsIntime(this.accessTime, time)) {
            return false;
        }
        return CryptoJS.AES.decrypt(token, this.key).toString(CryptoJS.enc.Utf8);
    }
    verifyRefreshToken(hash) {
        const [time, token] = [hash.slice(0, 8), hash.slice(8)];
        if (!SafeToken.IsIntime(this.refreshTime, time, true)) {
            return false;
        }
        return CryptoJS.AES.decrypt(token, this.key).toString(CryptoJS.enc.Utf8);
    }
    static IsIntime(number, lastTime, r) {
        const ms = Math.floor(Math.abs(new Date(Date.now()).getTime() -
            new Date(parseInt(lastTime, 16) * 1000).getTime()));
        if (r) {
            if (number > Math.round(ms / 86400_000)) {
                return true;
            }
            else {
                return false;
            }
        }
        else {
            if (number > ms) {
                return true;
            }
            else {
                return false;
            }
        }
    }
    static encode_timestamp() {
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
