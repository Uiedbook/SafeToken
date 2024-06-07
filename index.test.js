import { SafeToken } from "./dist/index.js";

const assert = (cond, ...logs) => {
  !cond && logs.length && console.log(...logs);
  if (!cond) throw new Error(`assertion failed`);
};

// auth
const Auth = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
});
// assertions
// tokens
console.time("t");
let token = await Auth.create({ email: "fridaycandours@gmail.com" });
console.log({
  token,
});
console.timeEnd("t");
console.log({
  decodedToken: await Auth.verify(token),
});

// auth
const Auth2 = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
  timeWindows: {
    // ? all provided in miliseconds
    access: 3600000 /*1 hour*/,
    refresh: 2592000000 /*1 month*/,
  },
});
// assertions
// tokens
let accessToken = await Auth2.create({ email: "fridaycandours@gmail.com" });
let refreshToken = await Auth2.create({ email: "fridaycandours@gmail.com" });
console.log({
  accessToken,
  refreshToken,
});
console.log({
  decodedAccessToken: await Auth2.verify(accessToken, "access"),
  decodedRefreshToken: await Auth2.verify(refreshToken, "refresh"),
});
