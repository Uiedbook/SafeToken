import pkg1 from "tweetnacl";
import pkg2 from "tweetnacl-util";
const { secretbox, randomBytes } = pkg1;
const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = pkg2;

export const generateKey = () => encodeBase64(randomBytes(secretbox.keyLength));

export const encrypt = (json, key) => {
  const keyUint8Array = decodeBase64(key);

  const nonce = randomBytes(secretbox.nonceLength);
  const messageUint8 = decodeUTF8(JSON.stringify(json));
  const box = secretbox(messageUint8, nonce, keyUint8Array);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  const base64FullMessage = encodeBase64(fullMessage);
  return base64FullMessage;
};

export const decrypt = (messageWithNonce, key) => {
  const keyUint8Array = decodeBase64(key);
  const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    secretbox.nonceLength,
    messageWithNonce.length
  );

  const decrypted = secretbox.open(message, nonce, keyUint8Array);

  if (!decrypted) {
    throw new Error("Could not decrypt message");
  }

  const base64DecryptedMessage = encodeUTF8(decrypted);
  return JSON.parse(base64DecryptedMessage);
};

const key = generateKey();
console.log(key.length);
const obj = { hello: "world" };
const encrypted = encrypt(obj, key);
const decrypted = decrypt(encrypted, key);
console.log(decrypted, obj, encrypted); // should be shallow equal
