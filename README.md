# SafeToken Generator/validator

SafeToken is a simplest Auth for generating secure and random tokens suitable for authentication purposes. It can be used to create access tokens, refresh tokens that is verifirable, stateless and can be invalidated anytime by calling reset.

## Features

- **Secure Token Generation:** Utilizes the a unique, random lenth string random string generation.
- **Auto Token Expiry Management:** Tokens have configurable expiration times.
- **Refresh Token Support:** Generates refresh tokens for secure token refresh mechanisms.

- 1KB~ size minified and fast token creation and verification logic.

## How It Works

The `SafeToken` class provides methods for generating access and refresh tokens. Tokens are generated using secure random strings to enhance security. Token expiration is managed, and new tokens can be generated based on configured time intervals.

## Usage

1. **Installation:**

```bash
npm i safetoken
```

```js
// auth.js

import { SafeToken } from "safetoken";
// auth
const Auth = new SafeToken();
//create a new access token
const accesToken = Auth.newToken();
// Generate a refresh token
const refreshToken = Auth.getRefreshToken();
// revoke access tokens
Auth.resetAccessToken();
// revoke refresh tokens
Auth.resetRefreshToken();
console.log({ accesToken, refreshToken });
```

## Custom Token Lifetimes

Default timeouts are 3600 secounds(access tokens) and 30 day(refresh tokens).

You can customize token expiration times during class instantiation. Adjust the TokenTime and RefreshDays parameters according to your application's requirements.

```js
// Example of customizing token lifetimes
const Auth = new SecureToken({
  TokenTime: 900, // Set access token lifetime to 15 minutes (in seconds)
  RefreshDays: 7, // Set refresh token lifetime to 7 days
});
```

## Contributing

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
