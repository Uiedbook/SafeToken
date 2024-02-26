# SafeToken Generator/validator

SafeToken is a simplest Auth for generating secure tokens suitable for authentication purposes.

We use it to create access tokens and refresh tokens that is verifirable and store encrypted data.

We can invalidate the tokens anytime by just calling resetToken.

SafeToken is easy for everyone.

## Features

- **Secure Token Generation:** Utilizes cryptographic token generation.
- **Super light-weight** 2KB~ size minified and fast token creation and verification logic.
- **Auto Token Expiry Management:** Tokens have configurable expiration times.
- **Refresh Token Support:** Generates refresh tokens for secure token refresh mechanisms.
- **Most fastest** create token and verify token functionality ever.

## How It Works

The `SafeToken` class provides methods for generating access and refresh tokens. Tokens are generated using crypto to enhance security. Token expiration is managed, and new tokens can be generated based on configured time intervals.

Refresh tokens can stored to disk with the rtStoreKey: fine-name option.

## Usage

```js
// in auth.js
import { SafeToken } from "safetoken";
const Auth = new SafeToken({
  encryptionKey: "xfn9P8L9rIpKtWKj68IZ3G865WfdYXNY", 
});
```

## Creating a New Token

```js
//create a new access token
const accesToken = Auth.newAccessToken(JSON.stringify({ name: "friday" }));
// Generate a refresh token
const refreshToken = Auth.newRefreshToken(JSON.stringify({ name: "friday" }));
```

## Verifying a Token

```js
const user_A = JSON.parse(Auth.verifyAccessToken(accesToken));
const user_R = JSON.parse(Auth.verifyRefreshToken(refreshToken));
console.log(user_A, user_R); // same thing
```

## Resetting Tokens

```js
// revoke access tokens
Auth.resetAccessToken();
// revoke refresh tokens
Auth.resetRefreshToken();
```

## Custom Token Lifetimes

Default timeouts are 3600000 seconds(access tokens) and 30 day(refresh tokens).

You can customize token expiration times during class instantiation. Adjust the TokenTime and RefreshDays parameters according to your application's requirements.

```js
// Example of customizing token lifetimes
const Auth = new SecureToken({
  TokenTime: 900, // Set access token lifetime to 15 minutes (in seconds)
  RefreshDays: 7, // Set refresh token lifetime to 7 days
});
```

1. **Installation:**

```bash
npm i safetoken
```

## test

```js
import { SafeToken } from "safetoken";

const assert = (cond) => {
  if (!cond) throw new Error(`assertion failed`);
};
// auth
const Auth = new SafeToken({
  encryptionKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
});
// tokens
let accesToken = Auth.newAccessToken(JSON.stringify({ name: "friday" }));
let refreshToken = Auth.newRefreshToken(JSON.stringify({ name: "friday" }));
// assertions
assert(JSON.parse(Auth.verifyAccessToken(accesToken)).name === "friday");
assert(JSON.parse(Auth.verifyRefreshToken(refreshToken)).name === "friday");

console.log({
  accesToken,
  refreshToken,
  accesTokenD: JSON.parse(Auth.verifyAccessToken(accesToken)),
  refreshTokenD: JSON.parse(Auth.verifyRefreshToken(refreshToken)),
});
```

## Contributing

This library provides a simple and secure way to manage authetication tokens with built-in encryption for added security.

If you find any issues or have suggestions for improvements, feel free to contribute by opening an issue or submitting a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Feel free to adjust the information based on your project's specific considerations and security requirements.

## Pizza Area

<a href="https://www.buymeacoffee.com/fridaycandour"><img src="https://img.buymeacoffee.com/button-api/?text=Buy us a coffee&emoji=&slug=fridaycandour&button_colour=FFDD00&font_colour=000000&outline_colour=000000&coffee_colour=ffffff" /></a>

cryptos -

- etheruen:0xD7DDD4312A4e514751A582AF725238C7E6dF206c
- Bitcoin: bc1q5548kdanwyd3y07nyjjzt5zkdxqec4nqqrd760
- LTC: ltc1qgqn6nqq6x555rpj3pw847402aw6kw7a25dc29w.
