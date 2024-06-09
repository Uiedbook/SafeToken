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
      ({ access: 3600000 /* 1 hour */ } as unknown as TimeWindow); // Default time window
  }

  async create(data: Record<string, string | number | boolean> = {}) {
    return await createHmacSha256Signature(data, this.secret, timestamp());
  }

  async verify(token: string, timeWindowKey: keyof TimeWindow = "access") {
    if (typeof token === "string") {
      return await verifyToken(
        token,
        this.secret,
        this.timeWindow[timeWindowKey]
      );
    }
    throw new Error("Invalid token");
  }

  decode(token: string) {
    const data = token.split(".")[2];
    const decodedData = base64UrlDecode(data);
    return JSON.parse(decodedData);
  }
}

async function createHmacSha256Signature(
  payload: Record<string, string | number | boolean>,
  secret: string,
  time: string
) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const tbuf = base64UrlEncode(time);
  const dataToSign = base64UrlEncode(JSON.stringify(payload));
  const data = dataToSign;
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(dataToSign + tbuf)
  );
  const signature = base64UrlEncode(
    String.fromCharCode(...new Uint8Array(signatureBuffer))
  );
  return `${time}.${signature}.${data}`;
}

async function verifyToken(token: string, secret: string, timeWindow: number) {
  const [time, signature, data] = token.split(".");
  if (!isIntime(timeWindow, time)) {
    throw new Error("Token expired");
  }

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const timeBase64 = base64UrlEncode(time);
  const dataToSign = data + timeBase64;
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(dataToSign)
  );
  const expectedSignature = base64UrlEncode(
    String.fromCharCode(...new Uint8Array(signatureBuffer))
  );

  if (timingSafeEqual(signature, expectedSignature)) {
    const decodedData = base64UrlDecode(data);
    return JSON.parse(decodedData) as Record<string, string | number | boolean>;
  }
  throw new Error("Invalid token");
}

const isIntime = (timeWindow: number, lastTime: string): boolean => {
  if (!timeWindow) {
    throw new Error("Invalid time window");
  }
  const lastTimeParsed = parseInt(lastTime, 16);
  if (isNaN(lastTimeParsed)) {
    throw new Error("Invalid timestamp format");
  }
  const ms = Math.abs(Date.now() - lastTimeParsed * 1000);
  return timeWindow > ms;
};

const timestamp = (): string => {
  const time = Math.floor(Date.now() / 1000);
  const buffer = new Uint8Array(4);
  buffer[3] = time & 0xff;
  buffer[2] = (time >> 8) & 0xff;
  buffer[1] = (time >> 16) & 0xff;
  buffer[0] = (time >> 24) & 0xff;
  return Array.from(buffer)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
};

function timingSafeEqual(a: string, b: string): boolean {
  if (a?.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function base64UrlEncode(str: string) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) {
    str += "=";
  }
  return atob(str);
}
