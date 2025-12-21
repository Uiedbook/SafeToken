import { SafeToken } from "./index.ts";

// in auth.js
const Auth = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
});

let token = await Auth.create({ email: "johndoe@gmail.com" });
console.log({
  token,
});

console.log({
  decodedToken: await Auth.verify(token + "a"),
});

//? only decode doesn't verify
console.log({
  decodedToken: await Auth.decode(token),
});
