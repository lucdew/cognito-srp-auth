# cognito_srp_auth

## Overview

Library to authenticate to a cognito user pool using SRP.

A binary is also produced to quickly perform a manual test from the command line.

It is mainly to demonstrate how to use the [cognito_srp](https://crates.io/cognito_srp) library.


## Run

```
cargo run -- --client-id CLIENT_ID --mfa MFA --password PASSWORD --pool-id POOL_ID --username USERNAME
```


