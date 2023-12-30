import { SafeToken } from "../lib/index.js";

const assert = (cond) => {
  if (!cond) throw new Error(` assertion failed`);
};
// auth
const Auth = new SafeToken({
  encryptionKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
});
// tokens
let accesToken = Auth.newAccessToken(
  JSON.stringify({ email: "fridaycandours@gmail.com" })
);
let refreshToken = Auth.newRefreshToken(
  JSON.stringify({ email: "fridaycandours@gmail.com" })
);
// assertions
assert(
  JSON.parse(Auth.verifyAccessToken(accesToken)).email ===
    "fridaycandours@gmail.com"
);
assert(
  JSON.parse(Auth.verifyRefreshToken(refreshToken)).email ===
    "fridaycandours@gmail.com"
);

console.log({
  accesToken,
  refreshToken,
  accesTokenD: JSON.parse(Auth.verifyAccessToken(accesToken)),
  refreshTokenD: JSON.parse(Auth.verifyRefreshToken(refreshToken)),
});
