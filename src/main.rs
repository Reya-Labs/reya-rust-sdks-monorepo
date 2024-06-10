use std::env;

use alloy::{
    contract,
    network::{EthereumSigner, TransactionBuilder},
    node_bindings::Anvil,
    providers::{Provider, ProviderBuilder},
    rpc::client::WsConnect,
    signers::wallet::LocalWallet,
    sol, sol_types,
};

use alloy::primitives::{address, Address};

use eyre;
use tokio;
//use futures_util::{future, StreamExt};
//use futures::task::Poll;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    coreProxy,
    "transactions/abi/COREPROXY.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    rUSDProxy,
    "transactions/abi/RUSDPROXY.json"
);

// // Get latest block number.
// let latest_block = provider.get_block_number().await?;
// println!("Latest block number: {latest_block}");

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let rpc_url = "https://rpc.reya.network".parse()?;
    let privateKey = env::var("PRIVATE_KEY").unwrap();
    println!("{privateKey}");
    let signer: LocalWallet = privateKey.parse().unwrap();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(EthereumSigner::from(signer))
        .on_http(rpc_url);

    // core create account

    let contract = coreProxy::new(
        "0xA763B6a5E09378434406C003daE6487FbbDc1a80".parse()?,
        provider,
    );

    let accountOwnerAddress = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");

    let builder = contract.createAccount(accountOwnerAddress);
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
