import { SafeToken } from "../lib/index.js";

const assert = (cond) => {
  if (!cond) throw new Error(` assertion failed`);
};
// auth
const Auth = new SafeToken({
  encryptionKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
});
// tokens
const accesToken = Auth.newToken();
const accesToken2 = Auth.newToken(JSON.stringify({ name: "friday" }));
const refreshToken = Auth.getRefreshToken();
// assertions
assert(Auth.verifyToken(accesToken) === true);
assert(JSON.parse(Auth.verifyToken(accesToken2)).name === "friday");
assert(Auth.verifyRefreshToken(refreshToken) === true);

console.log({
  accesToken,
  refreshToken,
  accesToken2: JSON.parse(Auth.verifyToken(accesToken2)),
});
