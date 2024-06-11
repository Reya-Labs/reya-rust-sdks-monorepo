use std::env;

use alloy::{
    network::EthereumSigner, providers::ProviderBuilder, signers::wallet::LocalWallet, sol,
};

use alloy::primitives::address;

use eyre;
use tokio;
//use futures_util::{future, StreamExt};
//use futures::task::Poll;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CoreProxy,
    "transactions/abi/CoreProxy.json"
);

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let rpc_url = "https://rpc.reya.network".parse()?;
    let private_key = env::var("PRIVATE_KEY").unwrap();
    println!("{private_key}");
    let signer: LocalWallet = private_key.parse().unwrap();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(EthereumSigner::from(signer))
        .on_http(rpc_url);

    // core create account

    let contract = CoreProxy::new(
        "0xA763B6a5E09378434406C003daE6487FbbDc1a80".parse()?,
        provider,
    );

    let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");

    let builder = contract.createAccount(account_owner_address);
    let receipt = builder.send().await?.get_receipt().await?;

    println!("{:?}", receipt);

    // rusd view

    // let contract = rUSDProxy::new(
    //     "0xa9F32a851B1800742e47725DA54a09A7Ef2556A3".parse()?,
    //     provider,
    // );

    // let rUSDProxy::totalSupplyReturn { _0 } = contract.totalSupply().call().await?;

    // println!("RUSD total supply is {_0}");

    // core view
    // let contract = coreProxy::new(
    //     "0xA763B6a5E09378434406C003daE6487FbbDc1a80".parse()?,
    //     provider,
    // );
    // let result = contract.getProtocolConfiguration().call().await?;

    eyre::Ok(())
}
