import { SafeToken } from "../src/index.js";

const assert = (cond) => {
  if (!cond) throw new Error(` assertion failed`);
};
// auth
const Auth = new SafeToken();
// tokens
const accesToken = Auth.newToken();
const refreshToken = Auth.getRefreshToken();
// assertions
assert(Auth.verifyToken(accesToken) === true);
assert(Auth.verifyRefreshToken(refreshToken) === true);

console.log({ accesToken, refreshToken });
