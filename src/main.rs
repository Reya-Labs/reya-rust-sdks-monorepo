use alloy::{
    primitives::{I256, U256},
    signers::wallet::LocalWallet,
};
use dotenv::dotenv;
use eyre;
use reya_rust_sdk::http_provider;
use simple_logger;
use std::env;
use tokio;
use tracing::info;
use url::Url;

#[tokio::main]
#[allow(dead_code)]
async fn main() -> eyre::Result<()> {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    dotenv().ok();

    let url = Url::parse("https://rpc.reya.network")?;
    let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

    let private_key = env::var("PRIVATE_KEY")
        .expect("Private key must be set as environment variable")
        .to_lowercase();

    let account_id = 11212u128; // externaly provided by trading party

    // create account
    /*{
            let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");
            let signer: LocalWallet = private_key.parse().unwrap();
            let transaction_hash = http_provider
                .create_account(signer, &account_owner_address)
                .await;

            info!("Created account, tx hash:{:?}", transaction_hash);
        }
    */

    // get account owner
    {
        let account_owner_address = http_provider.get_account_owner(account_id).await;
        info!("get account owner address,:{:?}", account_owner_address);
    }

    /**/
    // execute buy order
    {
        let signer: LocalWallet = private_key.parse().unwrap();

        let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
        let exchange_id = 1u128; //1=reya exchange
        let order_base: I256 = "+35000000000000000".parse().unwrap(); // 0.035 eth
        let order_price_limit: U256 = "4000000000000000000000".parse().unwrap(); // 4000 rusd
        let transaction_hash = http_provider
            .execute(
                signer,
                account_id,
                market_id,
                exchange_id,
                order_base,
                order_price_limit,
            )
            .await;
        info!("Execute match order, tx hash:{:?}", transaction_hash);
    }

    // execute sell order
    {
        let signer: LocalWallet = private_key.parse().unwrap();

        let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
        let exchange_id = 1u128; //1=reya exchange
        let order_base: I256 = "-35000000000000000".parse().unwrap(); // 0.035 eth
        let order_price_limit: U256 = "3000000000000000000000".parse().unwrap(); // 3000 rusd
        let transaction_hash = http_provider
            .execute(
                signer,
                account_id,
                market_id,
                exchange_id,
                order_base,
                order_price_limit,
            )
            .await;
        info!("Execute match order, tx hash:{:?}", transaction_hash);
    }

    Ok(())
}
