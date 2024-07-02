use alloy::{
    primitives::{address, I256, U256},
    signers::local::PrivateKeySigner,
};
use clap::*;
use dotenv::dotenv;
use eyre;
use reya_rust_sdk::{data_types, http_provider};
use rust_decimal::{prelude::*, Decimal};
use serde::{Deserialize, Serialize};
use serde_json;
use simple_logger;
use std::env;
use std::fs;
use tokio;
use tracing::*;
use url::Url;

/// order struct to execute orders in a batch
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonBatchOrder {
    pub account_id: u128,
    pub market_id: u128,
    pub client_order_id: String,
    pub order_type: String,
    /// side(+/- = buy/sell) + volume i256
    pub order_base: I256,
    /// stop price only set when order type = stop_loss
    pub stop_price: I256,
    pub price_limit: U256,
    pub signer_address: String,
    pub order_nonce: String,
    pub signature: String,
}

async fn create_account(private_key: &String, http_provider: &http_provider::HttpProvider) {
    let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");
    let signer: PrivateKeySigner = private_key.parse().unwrap();

    let transaction_hash = http_provider
        .create_account(signer, &account_owner_address)
        .await;

    info!("Created account, tx hash:{:?}", transaction_hash);
}

async fn get_account_owner(account_id: u128, http_provider: &http_provider::HttpProvider) {
    let account_owner_address = http_provider.get_account_owner(account_id).await;
    info!("get account owner address,:{:?}", account_owner_address);
}

async fn get_pool_price(market_id: u128, http_provider: &http_provider::HttpProvider) {
    let pool_price_result = http_provider.get_pool_price(market_id).await;
    match pool_price_result {
        Ok(pool_price) => {
            info!(
                "get pool price for market:{:?}, price:{:?}",
                market_id, //
                pool_price
            );
            let pool_price_str = pool_price.to_string();
            let price_result = Decimal::from_str(&pool_price_str);
            match price_result {
                Ok(p) => {
                    let divider = Decimal::new(1, 18);
                    info!("Get pool price:{:?}", p / divider);
                }
                Err(err) => {
                    error!("{:?}", err);
                }
            }
        }
        Err(err) => {
            error!("Failed to retreive pool price {:?}", err);
        }
    }
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
    let signer: PrivateKeySigner = private_key.parse().unwrap();

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

async fn execute_batch_orders(
    private_key: &String,
    http_provider: &http_provider::HttpProvider,
    batch_orders: &mut Vec<data_types::BatchOrder>,
) {
    let signer: PrivateKeySigner = private_key.parse().unwrap();

    let transaction_hash = http_provider.execute_batch(signer, batch_orders).await;
    info!("Execute batch orders, tx hash:{:?}", transaction_hash);
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> eyre::Result<()> {
    // default warn level logging
    simple_logger::init_with_level(log::Level::Info).unwrap();

    dotenv().ok();
    // sdk url: https://rpc.reya.network
    let mut commands = Command::new("sdk_test_app")
        .version("1.0")
        .about("Reya sdk test application")
        .arg(
            Arg::new("get-pool-price")
                .long("pool-price")
                .action(ArgAction::Set)
                .value_names(["sdk_url", "market_id"])
                .num_args(1..)
                .help("Gets the pool price for the required market id"),
        )
        .arg(
            Arg::new("batch-execute-orders")
                .long("batch-execute")
                .action(ArgAction::Set)
                .value_names(["sdk_url", "batch_order_file"])
                .num_args(1..)
                .help("Executes a batch of order from the input json order file"),
        )
        .arg(
            Arg::new("create-account")
                .long("create-account")
                .action(ArgAction::Set)
                .num_args(1..)
                .value_names(["sdk_url", "private_key"])
                .help("creates an account with the provided private key"),
        );

    let matches = commands.clone().get_matches();

    if matches.contains_id("get-pool-price") {
        // create account
        let packages: Vec<_> = matches
            .get_many::<String>("get-pool-price")
            .expect("market-id")
            .map(|s| s.as_str())
            .collect();

        let p1 = String::from(packages[0]); // sdk_url
        let p2 = String::from(packages[1]); // market_id

        let url = Url::parse(&p1).unwrap();
        let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

        // get pool price for market id
        let market_id: u128 = p2.parse().unwrap(); // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
        println!("calling get pool price {} {}", url, market_id);
        get_pool_price(market_id, &http_provider).await;
    } else
    // handle batche execute request
    if matches.contains_id("batch-execute-orders") {
        //
        let private_key = env::var("PRIVATE_KEY")
            .expect("Private key must be set as environment variable")
            .to_lowercase();
        let packages: Vec<_> = matches
            .get_many::<String>("batch-execute-orders")
            .expect("batch_order_file")
            .map(|s| s.as_str())
            .collect();

        let p1 = String::from(packages[0]); // sdk_url
        let p2 = String::from(packages[1]); // batch_order.json

        let url = Url::parse(&p1).unwrap();
        let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

        // get the json file with batch order json struct and load
        let batch_order_json_file: String = p2.parse().unwrap();

        println!("Execute batch order:{} {}", url, batch_order_json_file);

        let data = fs::read_to_string(batch_order_json_file) //
            .expect("Unable to read batch order json file");

        // todo make it a vector!
        let batch_order_json: JsonBatchOrder =
            serde_json::from_str(&data) //
                .expect("JSON does not have correct format.");

        println!("{:?}", batch_order_json);
    /*
    let mut batch_order_vec: Vec<data_types::BatchOrder> = vec![data_types::BatchOrder {
        account_id: batch_order_json.account_id,
        market_id: batch_order_json.market_id,
        exchange_id: data_types::REYA_EXCHANGE_ID,
        order_base: "000_000_000_000_000_000".parse().unwrap(),
        order_type: if batch_order_json.order_type == "StopLoss" {
            data_types::OrderType::StopLoss
        } else {
            data_types::OrderType::TakeProfit
        },
        stop_price: batch_order_json.stop_price,
        price_limit: batch_order_json.price_limit,
        signer_address: batch_order_json.signer_address.parse().unwrap(),
        // todo  eip712_signature: batch_order_json
        order_nonce: batch_order_json.order_nonce.parse().unwrap(),
        signature: batch_order_json.signature,
        is_executed_successfully: false,
    }];

    execute_batch_orders(&private_key, &http_provider, &mut batch_order_vec).await;
    */
    } else
    // handle create account request
    if matches.contains_id("create-account") {
        // create account
        let private_key = env::var("PRIVATE_KEY")
            .expect("Private key must be set as environment variable")
            .to_lowercase();
        let packages: Vec<_> = matches
            .get_many::<String>("create-account")
            .expect("sdk_url")
            .map(|s| s.as_str())
            .collect();
        let p1 = String::from(packages[0]); // sdk_url

        let url = Url::parse(&p1).unwrap();
        let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

        println!("Create account:{:?} {:?}", url, private_key);

        create_account(&private_key, &http_provider).await;
    } else {
        println!("missing arguments, use --help");
        let _ = commands.print_help();
    }

    //    tokio::runtime::Builder::new_multi_thread()
    //        .enable_all()
    //        .worker_threads(5)
    //        .build()
    //        .unwrap()
    //        .block_on(async {
    //            let url = Url::parse("https://rpc.reya.network").unwrap();
    //            let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);
    //
    //            let private_key = env::var("PRIVATE_KEY")
    //                .expect("Private key must be set as environment variable")
    //                .to_lowercase();
    //
    //            // create account
    //            //create_account(&private_key, &http_provider).await;
    //
    //            // get pool price for market id
    //            let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
    //            get_pool_price(market_id, &http_provider).await;
    //
    //            // get account owner
    //            let account_id = 11212u128; // externaly provided by trading party
    //            get_account_owner(account_id, &http_provider).await;
    //
    //            // execute buy market order
    //            {
    //                let exchange_id = 1u128; //1=reya exchange
    //                let order_base: I256 = "+35000000000000000".parse().unwrap(); // 0.035 eth
    //                let order_price_limit: U256 = "4000000000000000000000".parse().unwrap(); // 4000 rusd
    //                execute_order(
    //                    &private_key,
    //                    account_id,
    //                    &http_provider,
    //                    market_id,
    //                    exchange_id,
    //                    &order_base,
    //                    &order_price_limit,
    //                )
    //                .await;
    //            }
    //
    //            // execute sell market order
    //            {
    //                //let market_id = 1u128; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
    //                let exchange_id = 1u128; //1=reya exchange
    //                let order_base: I256 = "-35000000000000000".parse().unwrap(); // 0.035 eth
    //                let order_price_limit: U256 = "3000000000000000000000".parse().unwrap(); // 3000 rusd
    //                execute_order(
    //                    &private_key,
    //                    account_id,
    //                    &http_provider,
    //                    market_id,
    //                    exchange_id,
    //                    &order_base,
    //                    &order_price_limit,
    //                )
    //                .await;
    //            }
    //        });
    //
    Ok(())
}
