import { createHmac } from "node:crypto";

// TODO: implement SafeToken.adjust(timeWindowKey: string)\
// for invalidating token time range

export class SafeToken<
  TimeWindow extends Record<string, number> = { access: number }
> {
  private timeWindow: TimeWindow;
  private secret: string;
  constructor(init: { timeWindows?: TimeWindow; secret: string }) {
    if (!init.secret) {
      throw new Error("Please provide safetoken secret");
    }
    this.secret = init.secret;
    this.timeWindow =
      init.timeWindows ||
      ({ access: 3600000 /*1 hour*/ } as unknown as TimeWindow); //? default time window
  }
  create(data: Record<string, string | number | boolean> = {}) {
    return createHmacSha256Signature(data, this.secret, timestamp());
  }

  verify(token: string, timeWindowKey: keyof TimeWindow = "access") {
    if (typeof token === "string") {
      return verifyToken(token, this.secret, this.timeWindow[timeWindowKey]);
    }
    if (!token) {
      throw new Error("Invalid token");
    }
  }
  decode(token: string) {
    const buf = Buffer.from(token.split(".")[2], "base64").toString("utf-8");
    return JSON.parse(buf);
  }
}

function createHmacSha256Signature(
  payload: Record<string, string | number | boolean>,
  secret: string,
  time: string
) {
  const tbuf = rep(Buffer.from(time).toString("base64"));
  const dataToSign = rep(
    Buffer.from(JSON.stringify(payload)).toString("base64")
  );
  const data = rep(Buffer.from(JSON.stringify(payload)).toString("base64"));
  const signature = rep(
    createHmac("sha256", secret)
      .update(dataToSign + tbuf)
      .digest("base64")
  );
  return `${time}.${signature}.${data}`;
}

function verifyToken(token: string, secret: string, timeWindow: number) {
  const [time, signature, data] = token.split(".");
  //? time check
  if (!IsIntime(timeWindow, time)) {
    throw new Error("Token expired");
  }
  // ? would fail if the <time> is different from what's in the expected signature
  const dataToSign = data + rep(Buffer.from(time).toString("base64"));
  // ? signature check
  const expectedSignature = rep(
    createHmac("sha256", secret).update(dataToSign).digest("base64")
  );
  if (signature === expectedSignature) {
    const buf = Buffer.from(data, "base64").toString("utf-8");
    return JSON.parse(buf);
  }
  throw new Error("Invalid token");
}

const IsIntime = (number: number, lastTime: string): boolean => {
  if (!number) {
    throw new Error("Invalid time window");
  }
  const ms = Math.floor(
    Math.abs(
      new Date(Date.now()).getTime() -
        new Date(parseInt(lastTime, 16) * 1000).getTime()
    )
  );
  return number > ms;
};

const timestamp = (): string => {
  const time = ~~(new Date().getTime() / 1000);
  const buffer = Buffer.alloc(4);
  // 4-byte timestamp
  buffer[3] = time & 0xff;
  buffer[2] = (time >> 8) & 0xff;
  buffer[1] = (time >> 16) & 0xff;
  buffer[0] = (time >> 24) & 0xff;
  return buffer.toString("hex");
};

const rep = (a: string) =>
  a.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
