# Example Reya Rust Trading App

This repository contains a Rust application that interacts directly with the reya network rpc in order to execute a trade against the passive lp pool.

## Dependencies

Add the `alloy` crate to Cargo as it is not available in the Rust repository:
```sh
cargo add alloy --git https://github.com/alloy-rs/alloy
```

## Run the app
Before you can run the test application you need to set an environment variable that contains a private_key
export PRIVATE_KEY = your_private_key

## Building the documentation:
In order to create documentation, run: 
```
cargo doc --no-deps
```

## Deployments
In order to explore the reya core proxy contract, refer to the following cannon package link: 

https://usecannon.com/packages/reya-omnibus/1.0.0/1729-main/interact/reya-omnibus/CoreProxy/0xA763B6a5E09378434406C003daE6487FbbDc1a80