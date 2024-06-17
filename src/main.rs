use alloy::{
    primitives::{address, I256, U256},
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

async fn create_account(private_key: &String, http_provider: &http_provider::HttpProvider) {
    let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");
    let signer: LocalWallet = private_key.parse().unwrap();

    let transaction_hash = http_provider
        .create_account(signer, &account_owner_address)
        .await;

    info!("Created account, tx hash:{:?}", transaction_hash);
}

async fn get_account_owner(account_id: u128, http_provider: &http_provider::HttpProvider) {
    let account_owner_address = http_provider.get_account_owner(account_id).await;
    info!("get account owner address,:{:?}", account_owner_address);
}

async fn execute_order(
    private_key: &String,
    account_id: u128,
    http_provider: &http_provider::HttpProvider,
    market_id: u128,
    exchange_id: u128,
    order_base: &I256,
    order_price_limit: &U256,
) {
    let signer: LocalWallet = private_key.parse().unwrap();

    let transaction_hash = http_provider
        .execute(
            signer,
            account_id,
            market_id,
            exchange_id,
            order_base.clone(),
            order_price_limit.clone(),
        )
        .await;
    info!("Execute match order, tx hash:{:?}", transaction_hash);
}

#[allow(dead_code)]
fn main() -> eyre::Result<()> {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    dotenv().ok();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(5)
        .build()
        .unwrap()
        .block_on(async {
            let url = Url::parse("https://rpc.reya.network").unwrap();
            let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

            let private_key = env::var("PRIVATE_KEY")
                .expect("Private key must be set as environment variable")
                .to_lowercase();

            // create account
            create_account(&private_key, &http_provider).await;
            // get account owner
            let account_id = 11212u128; // externaly provided by trading party
            get_account_owner(account_id, &http_provider).await;

            // execute buy market order
            {
                let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
                let exchange_id = 1u128; //1=reya exchange
                let order_base: I256 = "+35000000000000000".parse().unwrap(); // 0.035 eth
                let order_price_limit: U256 = "4000000000000000000000".parse().unwrap(); // 4000 rusd
                execute_order(
                    &private_key,
                    account_id,
                    &http_provider,
                    market_id,
                    exchange_id,
                    &order_base,
                    &order_price_limit,
                )
                .await;
            }

            // execute sell market order
            {
                let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
                let exchange_id = 1u128; //1=reya exchange
                let order_base: I256 = "-35000000000000000".parse().unwrap(); // 0.035 eth
                let order_price_limit: U256 = "3000000000000000000000".parse().unwrap(); // 3000 rusd
                execute_order(
                    &private_key,
                    account_id,
                    &http_provider,
                    market_id,
                    exchange_id,
                    &order_base,
                    &order_price_limit,
                )
                .await;
            }
        });

    Ok(())
}
