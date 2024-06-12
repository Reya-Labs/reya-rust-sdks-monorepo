mod reya_network;
use crate::reya_network::http_provider;
use alloy::{
    primitives::{I256, U256},
    signers::wallet::LocalWallet,
};
use eyre;
use std::env;
use tokio;
use url::Url;

#[tokio::main]
#[allow(dead_code)]
async fn main() -> eyre::Result<()> {
    let url = Url::parse("https://rpc.reya.network")?;
    let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

    let private_key = env::var("PRIVATE_KEY").unwrap();
    /*
        // create account
        {
            let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");
            let signer: LocalWallet = private_key.parse().unwrap();
            let account_id = http_provider
                .create_account(signer, &account_owner_address)
                .await;

            println!("Created account, account_id:{:?}", account_id);
        }
    */
    // execute order
    {
        let signer: LocalWallet = private_key.parse().unwrap();

        let account_id = 734u128; // externaly provided by trading party
        let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
        let exchange_id = 1u128; //1=reya exchange
        let order_base: I256 = "1".parse().unwrap();
        let order_price_limit: U256 = "0".parse().unwrap();
        let execution_result = http_provider
            .execute(
                signer,
                account_id,
                market_id,
                exchange_id,
                order_base,
                order_price_limit,
            )
            .await;
        println!(
            "Execute match order, contract address:{:?}",
            execution_result
        );
    }

    // rusd view
    // let contract = rUSDProxy::new(
    //"0xa9F32a851B1800742e47725DA54a09A7Ef2556A3".parse()?,
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

    Ok(())
}
