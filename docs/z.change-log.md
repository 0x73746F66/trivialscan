# Change Log

## 0.2.1 Oct 8th 2021

- Added structured documentation
- fingerprints now match the browser format when output on cli
- moved static methods from `Validator` to the `util` module
- dropped redundant `host` and `port` from `Validator.verify()` for simplicity

## 0.2.0 Oct 7th 2021

- Completed the `clientAuth` implementation, which broke backwards compatibility.
- All OpenSSL validations are now performed and captured (instead of ignored and re-implemented like other libraries are doing).

## 0.1.7 Oct 5th 2021

Fixed some bugs and added some `clientAuth` functions without breaking backwards compatibility.
This release is usable for a more thorough verification TLS than anything else I've compared to so far.

## 0.1.1 Oct 4th 2021

Initial public release which may be of little use, please upgrade ASAP