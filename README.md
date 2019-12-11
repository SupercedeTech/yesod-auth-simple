# yesod-auth-simple

This library is a [Yesod](https://www.yesodweb.com) [subsite](https://www.yesodweb.com/book/creating-a-subsite) that serves as a basis for user management and authentication in the traditional way (that is, users and their credentials are stored in a database you control). It includes both the backend route handlers and the frontend UI for login, registration, and password resets, which can optionally be extended or replaced. As a user, you need to provide implementations of sending appropriate emails, and user persistence. Features include:

* Ready-to-go route handlers and UI for login, registration and password reset flows
* Password hashing and reset tokens are handled for you via Colin Percival's [Scrypt](https://hackage.haskell.org/package/scrypt) implementation. Just write the functions that store them in the database.
* A colourful password strength meter with feedback using [zxcvbn](https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/) (Traditional password checking based on length is also supported).
* Sensible splitting of UI into subcomponents so that you can use, for example, just the password input and strength meter in your own larger-scale forms.

## Installation

`yesod-auth-simple` is not yet on Hackage. For now, we recommend pulling directly from GitHub using Nix or Stack (instructions for Stack [here](https://docs.haskellstack.org/en/stable/faq/#i-need-to-use-a-package-or-version-of-a-package-that-is-not-available-on-hackage-what-should-i-do)). For nix, you will need to:

1. copy the included `yesod-auth-nix.nix` derivation function into your project somewhere,
2. change the `src` attribute to reference this remote repository (e.g., using [fetchgit](https://nixos.org/nixpkgs/manual/#chap-pkgs-fetchers)).
3. build your project using a nixpkgs config that adds this package to the `haskell.packages.overrides`. More details on this Nix and Haskell workflow can be found [here](https://github.com/Gabriel439/haskell-nix/blob/master/project1/README.md).

## Usage

The library is built around the `YesodAuthSimple` type class. To use this package, you should write an instance of this class for the same type that instatiates the `Yesod` and `YesodAuth` type classes. To make the final connection, add `Yesod.Auth.Simple.authSimple` to the `YesodAuth` instance's `authPlugins` list.

```haskell
data App = ...

instance Yesod App

instance YesodAuth App where
  -- Refer to documentation for yesod-auth: http://hackage.haskell.org/package/yesod-auth
  type AuthId App = Key User -- For some User datatype, often derived from Persistent models
  loginDest _ = HomeR
  logoutDest _ = HomeR
  authPlugins _ = [ authSimple ]
  getAuthId = return . fromPathPiece . credsIdent
  maybeAuthId = defaultMaybeAuthId

instance YesodAuthSimple App where
  type AuthSimpleId App = Key User -- Uses the same  User datatype as in YesodAuth

  passwordCheck = Zxcvbn Safe (Vec.fromList ["yesod"])

  insertUser email encryptedPass = -- Add the user to your database!
  updateUserPassword userId encryptedPass = ...

  getUserId userEmail = -- Look in the DB for a corresponding user ID if one exists
  getUserPassword userId = -- Look in the DB and return a Crypto.Scrypt.EncryptedPass
  getUserModified userId = ...

  sendVerifyEmail email urlToSend = ...
  sendResetPasswordEmail email urlToSend = ...

  afterPasswordRoute = -- e.g. redirect to the homepage after resetting password
  onRegisterSuccess  = -- e.g. redirect them to the homepage after registering
```

The rest of the typeclass consists of various Yesod [widget](https://www.yesodweb.com/book/widgets) [templates](https://www.yesodweb.com/book/shakespearean-templates) with default implementations. Override any as you see fit. The default templates are exported at the module's top level, so you can use them inside your own larger container widgets.

Full details on the class functions can be found in the Hackage docs. An example of writing an instance for testing purposes can be found [here](https://github.com/riskbook/yesod-auth-simple/blob/master/test/ExampleApp.hs).

## Security notes

This libary is not yet on Hackage and some aspects are still missing, in particular: CSRF protection. Check the [issues](https://github.com/riskbook/yesod-auth-simple/issues) before using.

This library will send POST requests containing the user's password (including as they type it via an XHR when you choose to use the Zxcvbn strength algorithm). It is therefore **vital** that you do not log the request bodies of these routes to avoid storing passwords in plaintext logs on your server. Sensitive routes are currently: loginR, setPasswordR, confirmR, and passwordStrengthR. We are investigating ways to improve developer experience here.

Please also beware of logging the HTTP `Referrer` header and confirmation/reset URLs themselves, which at certain points will include the account confirmation or password reset token.

## More pleasing authentication URLs

By default, all route URLs from this library are quite verbose: `/auth/page/simple/<login|register|..>`. If you would like short URLs (e.g. `/login`), then you should:

1. Use the `urlParamRenderOverride` function in your `Yesod` instance to change all `PluginR "simple" _` routes plus the `LoginR` and `LogoutR` routes to their short versions. Tip: Case on the route types (e.g. `LoginR`) and return absolute URLs.
2. Ensure incoming requests to the short URLs route to the extended URL handlers. Tip: Check out `rewritePureWithQueries` and its documentation in the `wai-extra` package.

Note that step 1 is for Yesod's type-safe routing while step 2 is for HTTP requests themselves. We will try to ease the developer experience of this in the future if possible!

## Contributing

Get started by running `nix-shell` from the project root directory and then use `cabal` and `ghci` from there. Run the tests from inside ghci using the included `:test` command.
