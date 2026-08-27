#[allow(dead_code)]
use alloy::primitives::{address, I256, U256};
use clap::*;
use core::result::Result::Ok;
use dotenv::dotenv;
use reya_rust_sdk::{
    data_types,
    http_provider::{self, extract_execute_batch_outputs},
};
use rust_decimal::{prelude::*, Decimal};
use serde::{Deserialize, Serialize};
use serde_json;
use simple_logger;
use std::fs;
use tokio;
use tracing::*;
use eyre::WrapErr;

/// order input struct to execute orders in a batch
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

async fn create_account(
    private_key: &str,
    http_provider: &http_provider::HttpProvider,
) -> eyre::Result<()> {
    let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");
    let transaction_hash = http_provider
        .create_account(private_key, &account_owner_address)
        .await?;

    info!("Created account, tx hash:{:?}", transaction_hash);
    Ok(())
}

async fn _get_account_owner(account_id: u128, http_provider: &http_provider::HttpProvider) {
    let account_owner_address = http_provider.get_account_owner(account_id).await;
    info!("get account owner address,:{:?}", account_owner_address);
}

async fn get_pool_price(
    market_id: u128,
    http_provider: &http_provider::HttpProvider,
) -> eyre::Result<()> {
    let pool_price = http_provider.get_pool_price(market_id).await?;
    info!(
        "Get pool price for market {:?}, raw price {:?}",
        market_id, pool_price
    );

    let price = Decimal::from_str(&pool_price.to_string())
        .wrap_err("Failed to convert the pool price to a decimal")?;
    debug!(
        "Price multiplier: {:?}, raw price: {:?}",
        data_types::PRICE_MULTIPLIER,
        price
    );
    info!(
        "Get pool price for market {}, normalized price {:?}",
        market_id,
        price / data_types::PRICE_MULTIPLIER
    );

    Ok(())
}

async fn get_execute_batch_receipt_logs(
    batch_execute_hash: &str,
    http_provider: &http_provider::HttpProvider,
) -> eyre::Result<()> {
    let transaction_hash = batch_execute_hash
        .parse()
        .wrap_err("Invalid batch execution transaction hash")?;
    let batch_execute_receipt_option = http_provider
        .get_transaction_receipt(transaction_hash)
        .await;

    match batch_execute_receipt_option {
        Some(batch_execute_receipt) => {
            let results = extract_execute_batch_outputs(&batch_execute_receipt);
            for batch_execute_output in results {
                match &batch_execute_output.reason_error {
                    None => {
                        // The order executed without an error.
                        info!(
                            "Order executed successfully {:?}, {:?}",
                            batch_execute_hash, batch_execute_output,
                        );
                    }
                    Some(reason_error_code) => {
                        error!("ErrorCode={:?}", reason_error_code);
                    }
                }
            }
        }
        None => {
            return Err(eyre::eyre!(
                "Transaction receipt was not available after the polling window"
            ));
        }
    }

    Ok(())
}

#[allow(dead_code)]
async fn execute_order(
    sdk_config: &data_types::SdkConfig,
    account_id: u128,
    http_provider: &http_provider::HttpProvider,
    market_id: u128,
    exchange_id: u128,
    order_base: &I256,
    order_price_limit: &U256,
) {
    let transaction_hash = http_provider
        .execute(
            &sdk_config.private_key,
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
    // default warn level logging
    simple_logger::init_with_level(log::Level::Debug)
        .wrap_err("Failed to initialize the logger")?;

    dotenv().ok();
    // sdk url: https://rpc.reya.network
    let mut commands = Command::new("sdk_test_app")
        .version("1.0")
        .about("Reya sdk test application")
        .arg(
            Arg::new("get-pool-price")
                .long("pool-price")
                .action(ArgAction::Set)
                .value_names(["market_id"])
                .num_args(1..)
                .help("Gets the pool price for the required market id"),
        )
        .arg(
            Arg::new("get-execute-batch-receipt-outputs")
                .long("get-execute-batch-receipt-outputs")
                .action(ArgAction::Set)
                .value_names(["batch_execute_hash"])
                .num_args(1..)
                .help("Gets the batch execute outputs from event logs"),
        )
        .arg(
            Arg::new("batch-execute-orders")
                .long("batch-execute")
                .action(ArgAction::Set)
                .value_names(["batch_order_file"])
                .num_args(1..)
                .help("Executes a batch of order from the input json order file"),
        )
        .arg(
            Arg::new("create-account")
                .long("create-account")
                .action(ArgAction::Set)
                .value_names(["private_key"])
                .help("creates an account with the provided private key"),
        );

    let matches = commands.clone().get_matches();

    if matches.contains_id("get-pool-price") {
        // create account
        let packages: Vec<_> = matches
            .get_many::<String>("get-pool-price")
            .ok_or_else(|| eyre::eyre!("Missing market id argument"))?
            .map(|s| s.as_str())
            .collect();

        let p0 = String::from(packages[0]); // market_id

        let sdk_config = data_types::load_enviroment_config()?;
        let http_provider: http_provider::HttpProvider =
            http_provider::HttpProvider::new(&sdk_config);

        // get pool price for market id
        let market_id: u128 = p0
            .parse()
            .wrap_err("Market id must be an unsigned integer")?; // 1=eth/rUSD, 2=btc/rUSD (instrument symbol)
        println!(
            "Calling get pool price from {} for market {}",
            sdk_config.rpc_url, market_id
        );
        get_pool_price(market_id, &http_provider).await?;
    } else if matches.contains_id("get-execute-batch-receipt-outputs") {
        // create account
        let packages: Vec<_> = matches
            .get_many::<String>("get-execute-batch-receipt-outputs")
            .ok_or_else(|| eyre::eyre!("Missing batch execution hash argument"))?
            .map(|s| s.as_str())
            .collect();

        let sdk_config = data_types::load_enviroment_config()?;
        let http_provider: http_provider::HttpProvider =
            http_provider::HttpProvider::new(&sdk_config);

        let batch_execute_hash = packages[0];
        debug!("Get logs from RPC endpoint {}", sdk_config.rpc_url);
        get_execute_batch_receipt_logs(batch_execute_hash, &http_provider).await?;
    } else
    // handle batche execute request
    if matches.contains_id("batch-execute-orders") {
        //
        let packages: Vec<_> = matches
            .get_many::<String>("batch-execute-orders")
            .ok_or_else(|| eyre::eyre!("Missing batch order file argument"))?
            .map(|s| s.as_str())
            .collect();

        let p1 = String::from(packages[0]); // batch_order.json

        let sdk_config = data_types::load_enviroment_config()?;
        let _http_provider: http_provider::HttpProvider =
            http_provider::HttpProvider::new(&sdk_config);

        // Read the batch order JSON file and deserialize its contents.
        let batch_order_json_file = p1;

        println!(
            "Execute batch order:{} {}",
            sdk_config.rpc_url, batch_order_json_file
        );

        let data = fs::read_to_string(&batch_order_json_file)
            .wrap_err("Unable to read the batch order JSON file")?;

        let _batch_order_json: JsonBatchOrder = serde_json::from_str(&data)
            .wrap_err("The batch order JSON does not have the expected format")?;

        println!("Loaded batch order data from {}", batch_order_json_file);
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
        //let private_key = env::var("PRIVATE_KEY")
        //    .expect("Private key must be set as environment variable")
        //    .to_lowercase();
        //let packages: Vec<_> = matches.get_many::<String>("create-account").collect();

        let sdk_config = data_types::load_enviroment_config()?;
        let http_provider: http_provider::HttpProvider =
            http_provider::HttpProvider::new(&sdk_config);

        println!("Create account using RPC endpoint {}", sdk_config.rpc_url);

        create_account(&sdk_config.private_key, &http_provider).await?;
    } else {
        println!("missing arguments, use --help");
        commands.print_help()?;
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
