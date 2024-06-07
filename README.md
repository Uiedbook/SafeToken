# SafeToken Generator/validator

SafeToken is a simplest Auth for generating secure tokens suitable for authentication purposes.

We use it to create access tokens and refresh tokens that is verifirable and store signed data.

SafeToken is easy for everyone.

## Features

- **Secure Tokens:** Utilizes cryptographic signature.
- **Modern api** Built using modern nodejs crypto APIs.
- **Most fastest** Blazingly fast .create .verify methods.
- **Fully Typed** SafeToken is written in typescript and fully typed.
- **Super light-weight** 2KB~ size minified and fast token creation and verification logic.

## How It Works

The `SafeToken` class provides methods for generating tokens. Tokens are generated using crypto to enhance security. Token expiration is managed, and new tokens can be generated based on configured time intervals.

## Usage

```js
// in auth.js
const Auth = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
});
```

## Creating a token

```js
let token = await Auth.create({ email: "johndoe@gmail.com" });
console.log({
  token,
});
```

## Verifying a Token

```js
console.log({
  decodedToken: await Auth.verify(token),
});

//? only decode doesn't verify
console.log({
  decodedToken: await Auth.decode(token),
});
```

## Custom Token Lifetimes Example

The default timeout is 3600000 miniseconds = 1 hour.

You can customize token expiration times during class instantiation. by provide timewindows according to your application's requirements.

### creating custom time windows

```js
// Example of customizing token lifetimes
const Auth2 = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
  // your custom time windows
  timeWindows: {
    // ? all provided in miliseconds
    access: 3600000 /*1 hour*/,
    refresh: 2592000000 /*1 month*/,
  },
});
```

### Usaging custom time windows

```js
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
```

1. **Installation:**

```bash
npm i safetoken
```

## Contributing

This library provides a simple and secure way to manage authetication tokens with built-in cryptographic encryption for added security.

If you find any issues or have suggestions for improvements, feel free to contribute by opening an issue or submitting a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Feel free to adjust the information based on your project's specific considerations and security requirements.

## Pizza Area

Support me via cryptos -

- BTC: `bc1q228fnx44ha9y5lvtku70pjgaeh2jj3f867nwye`
- ETH: `0xd067560fDed3B1f3244d460d5E3011BC42C4E5d7`
- LTC: `ltc1quvc04rpmsurvss6ll54fvdgyh95p5kf74wppa6`
- TRX: `THag6WuG4EoiB911ce9ELgN3p7DibtS6vP`
