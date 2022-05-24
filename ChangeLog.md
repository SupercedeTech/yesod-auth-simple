# Revision history for `yesod-auth-simple`

This format is based on [Keep A Changelog](https://keepachangelog.com/en/1.0.0).

## Unreleased

## 1.1.0 - 2022-05-23

+ Make it build with ghc 9 by getting rid of AuthHandler in the typeclass
  and use the more general MonadAuthHandler.

## 1.0.0 - 2022-05-04

### Added

* `YesodAuthSimple` class methods:
  - `isConfirmationPending` to check if an email is waiting for confirmation
  - `onEmailAlreadyExist` to specify an action if the email is already registered.
  - `confirmationEmailResentTemplate` to notify user that a confirmation email has been resent
* Route `getConfirmationEmailResentR` to redirect user after the confirmation email has been resent
* Functions `getError`, `setError`, `clearError` added to export list

### Changed

* `postRegisterR` implementation logic. If you don't implement the new `YesodAuthSimple` methods,
  it will work just like the old implementation

## 0.0.0  -- 2018-12-02

* First version. Not exactly ready for release.
