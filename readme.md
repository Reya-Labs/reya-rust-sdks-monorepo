# Example Reya Rust Trading App

This repository contains a Rust application that interacts with the Reya network in order to execute a trade against the passive lp pool.

# Dependencies
Add alloy to cargo because it is not in the rust repo: cargo add alloy --git https://github.com/alloy-rs/alloy

# Run the app
before you can run the test application you need to set an environment variable that contains a private_key
export PRIVATE_KEY = your_private_key

# Building the documentation:
 run: 'cargo doc --no-deps' to build all create documentation

# Deployments

https://usecannon.com/packages/reya-omnibus/1.0.0/1729-main/interact/reya-omnibus/CoreProxy/0xA763B6a5E09378434406C003daE6487FbbDc1a80