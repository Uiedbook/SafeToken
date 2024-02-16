import { SafeToken } from "../dist/index.js";

const assert = (cond, ...logs) => {
  !cond && logs.length && console.log(...logs);
  if (!cond) throw new Error(`assertion failed`);
};
// auth
const Auth = new SafeToken({
  encryptionKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  timeWindow: 3600_000,
  rtDays: 365,
});
// assertions
console.time("t");
for (let t = 0; t < 1_00_000; t++) {
  // tokens
  let refreshToken = Auth.newRefreshToken(
    JSON.stringify({ email: "fridaycandours@gmail.com" })
  );
  let accesToken = Auth.newAccessToken(
    JSON.stringify({ email: "fridaycandours@gmail.com" })
  );
  console.log({
    // refreshToken,
    // accesToken,
    aa: Auth.verifyAccessToken(accesToken),
    rt: Auth.verifyRefreshToken(refreshToken),
  });
  assert(
    JSON.parse(Auth.verifyAccessToken(accesToken)).email ===
      "fridaycandours@gmail.com"
  );
  assert(
    JSON.parse(Auth.verifyRefreshToken(refreshToken)).email ===
      "fridaycandours@gmail.com",
    JSON.parse(Auth.verifyRefreshToken(refreshToken))
  );
  // console.log(t);
}
console.timeEnd("t");
// console.log({
//   accesToken,
//   refreshToken,
//   accesTokenD: JSON.parse(Auth.verifyAccessToken(accesToken)),
//   refreshTokenD: JSON.parse(Auth.verifyRefreshToken(refreshToken)),
// });
