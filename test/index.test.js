import { SafeToken } from "../dist/index.js";

const assert = (cond, ...logs) => {
  !cond && logs.length && console.log(...logs);
  if (!cond) throw new Error(`assertion failed`);
};
// auth
const Auth = new SafeToken({
  encryptionKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  timeWindow: 3600,
  rtDays: 365,
});
console.log(Auth);
// assertions
// tokens
console.time("t");
let refreshToken = Auth.newRefreshToken(
  JSON.stringify({ email: "fridaycandours@gmail.com" })
);
console.timeEnd("t");
let accesToken = Auth.newAccessToken(
  JSON.stringify({ email: "fridaycandours@gmail.com" })
);
console.log({
  accesToken,
  refreshToken,
  accesTokenD: JSON.parse(Auth.verifyAccessToken(accesToken)),
  refreshTokenD: JSON.parse(Auth.verifyRefreshToken(refreshToken)),
});
