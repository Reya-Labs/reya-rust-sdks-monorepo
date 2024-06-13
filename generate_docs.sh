#!/bin/sh

# Generate documentation
cargo doc --no-deps
cd target/doc/
zip  -r ../../docs/reya-rust-sdk.zip ./reya_rust/
cd -