use alloy::{
    primitives::{address, I256, U256},
    signers::local::PrivateKeySigner,
};
use clap::*;
use dotenv::dotenv;
use eyre;
use reya_rust_sdk::http_provider;
use rust_decimal::{prelude::*, Decimal};
use simple_logger;
use std::env;
use tokio;
use tracing::*;
use url::Url;

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

async fn get_pool_price(market_id: u128, http_provider: &http_provider::HttpProvider) -> Decimal {
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
                    info!("Pool price:{:?}", p / divider);
                    return p / divider;
                }
                Err(err) => {
                    error!("{:?}", err);
                    return Decimal::new(0, 0);
                }
            }
        }
        Err(err) => {
            error!("Failed to retreive pool price {:?}", err);
            return Decimal::new(0, 0);
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

#[allow(dead_code)]
#[tokio::main]
async fn main() -> eyre::Result<()> {
    //let logger = simple_logger::SimpleLogger::new()        .with_level(simple_logger::SimpleLogger::level::info)        //.env()        //.init()        ;
    simple_logger::init_with_level(log::Level::Warn).unwrap();

    dotenv().ok();

    let mut commands = Command::new("sdk_test_app")
        .version("1.0")
        //.author("Author Name <author@example.com>")
        .about("Reya sdk test application")
        .arg(
            Arg::new("get-pool-price")
                .long("pool-price")
                //.value_name("market_id")
                .action(ArgAction::Set)
                .num_args(1..)
                .help("Gets the pool price for the required market id"),
        )
        .arg(
            Arg::new("create-account")
                .long("create-account")
                .action(ArgAction::Set)
                .num_args(1..)
                //.value_name("private_key")
                .help("creates an account with the provided private key"),
        );

    let matches = commands.clone().get_matches();

    // You can check the presence of a flag like this:
    let url = Url::parse("https://rpc.reya.network").unwrap();
    let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);

    if matches.contains_id("get-pool-price") {
        // create account
        let packages: Vec<_> = matches
            .get_many::<String>("get-pool-price")
            .expect("market-id")
            .map(|s| s.as_str())
            .collect();

        let p1 = String::from(packages[0]);

        // get pool price for market id
        let market_id: u128 = p1.parse().unwrap(); // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
        println!("calling get pool price for market:{}", market_id);

        get_pool_price(market_id, &http_provider).await;
    } else if matches.contains_id("create-account") {
        // create account
        let packages: Vec<_> = matches
            .get_many::<String>("create-account")
            .expect("private-key")
            .map(|s| s.as_str())
            .collect();
        let p = String::from(packages[0]).to_lowercase();
        create_account(&p, &http_provider).await;
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
