import { SafeToken } from "../lib/index.js";

const assert = (cond) => {
  if (!cond) throw new Error(` assertion failed`);
};
// auth
const Auth = new SafeToken({
  encryptionKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
});
// tokens
let accesToken = Auth.newAccessToken();
let accesToken2 = Auth.newAccessToken(JSON.stringify({ name: "friday" }));
let refreshToken = Auth.newRefreshToken();
// assertions
assert(Auth.verifyToken(accesToken) === true);
assert(JSON.parse(Auth.verifyToken(accesToken2)).name === "friday");
assert(Auth.verifyRefreshToken(refreshToken) === true);

console.log({
  accesToken,
  refreshToken,
  accesToken2,
  accesToken2Data: JSON.parse(Auth.verifyToken(accesToken2)),
});

export const Aut2 = new SafeToken({
  encryptionKey: "1fn9P849rIpK82Kj68IZ3G8679fdYX82",
  rtStoreKey: "_token",
  rtDays: 90,
});

// tokens
accesToken = Auth.newAccessToken();
accesToken2 = Auth.newAccessToken(JSON.stringify({ name: "friday" }));
refreshToken = Auth.newRefreshToken();
// assertions
assert(Auth.verifyToken(accesToken) === true);
assert(JSON.parse(Auth.verifyToken(accesToken2)).name === "friday");
assert(Auth.verifyRefreshToken(refreshToken) === true);

console.log({
  accesToken,
  refreshToken,
  accesToken2,
  accesToken2Data: JSON.parse(Auth.verifyToken(accesToken2)),
});
