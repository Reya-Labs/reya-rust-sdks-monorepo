use alloy::primitives::{Address, I256, U256};
use alloy_primitives::Bytes;
use dotenv::dotenv;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

use crate::solidity::OrderGatewayProxy;

pub const PRICE_MULTIPLIER: Decimal = dec!(1_000_000_000_000_000_000);
pub const WAD_MULTIPLIER: f64 = 1000000000000000000.0;

///
/// configuration struct for the sdk
///
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SdkConfig {
    pub core_proxy_address: String,
    pub order_gateway_contract_address: String,
    pub passiv_perp_instrument_address: String,
    pub oracle_adapters_contract_address: String,
    pub stork_api_key: String,
    pub private_key: String,
    pub rpc_url: Url,
    pub counter_party_id: u128,
}

pub fn load_enviroment_config() -> SdkConfig {
    dotenv().ok();

    let core_proxy_address = env::var("CORE_PROXY_ADDRESS")
        .expect("Core proxy address must be set as environment variable")
        .to_lowercase();

    let order_gateway_contract_address = env::var("ORDER_GATEWAY_CONTRACT_ADDRESS")
        .expect("Order gateway contract address must be set as environment variable")
        .to_lowercase();

    let passiv_perp_instrument_address = env::var("PASSIVE_PERP_INSTRUMENT_CONTRACT_ADDRESS")
        .expect("Passive perp instrument address must be set as environment variable")
        .to_lowercase();

    let oracle_adapters_contract_address = env::var("ORACLE_ADAPTERS_CONTRACT_ADDRESS")
        .expect("Oracle adapters contract address must be set as environment variable")
        .to_lowercase();

    let private_key = env::var("PRIVATE_KEY")
        .expect("Private key must be set as environment variable")
        .to_lowercase();

    let stork_api_key = env::var("STORK_API_KEY")
        .expect("Stork api key must be set as environment variable")
        .to_lowercase();

    let rpc_url = Url::parse(
        env::var("RPC_URL")
            .expect("RPC Url must be set as environment variable")
            .to_lowercase()
            .as_str(),
    );

    let counter_party_id = u128::from_str_radix(
        env::var("COUNTER_PARTY_ID")
            .expect("Counter party id 2 or 4 and must be set as environment variable")
            .as_str(),
        10,
    );

    let sdk_config = SdkConfig {
        core_proxy_address,
        order_gateway_contract_address,
        passiv_perp_instrument_address,
        oracle_adapters_contract_address,
        stork_api_key,
        private_key,
        rpc_url: rpc_url.unwrap(),
        counter_party_id: counter_party_id.unwrap(),
    };

    return sdk_config;
}

#[allow(dead_code)]

// exchanges
pub const REYA_EXCHANGE_ID: u128 = 2u128; //1=reya exchange during contest

// multicall3 contract address
pub const MULTICALL_ADDRESS: &str = "0xcA11bde05977b3631167028862bE2a173976CA11";

// call object for multicall
#[derive(Debug, Serialize, Deserialize)]
pub struct Call {
    pub target: Address,
    pub calldata: Vec<u8>,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug)]
pub enum CommandType {
    Deposit = 0,
    Withdraw,
    DutchLiquidation,
    MatchOrder,
    TransferMarginAccount,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum OrderType {
    StopLoss = 0,
    TakeProfit = 1,
    Limit = 2,
}

/// order struct to execute orders in a batch
#[derive(Debug)]
pub struct BatchOrder {
    pub order_id: String,
    pub account_id: u128,
    pub market_id: u128,
    pub exchange_id: u128,
    pub order_type: OrderType,
    /// side(+/- = buy/sell) + volume/quantity
    pub order_base: Decimal,
    pub pool_price: Decimal,
    /// stop price only set when order type = stop_loss
    pub trigger_price: Decimal,
    pub price_limit: U256,
    pub is_long: bool,
    pub signer_address: Address,
    pub order_nonce: U256,
    pub eip712_signature: OrderGatewayProxy::EIP712Signature,
}

#[allow(dead_code)]
pub struct MarginInfo {
    /// The collateral token for which the information below is defined
    pub collateral: Address,
    /// These are all amounts that are available to contribute to cover margin requirements.
    pub margin_balance: I256,
    /// The real balance is the balance that is in ‘cash’, that is, actually held in the settlement
    /// collateral and not as value of an instrument which settles in that collateral
    pub real_balance: I256,
    /// Difference between margin balance and initial margin requirement
    pub initial_delta: I256,
    /// Difference between margin balance and maintenance margin requirement
    pub maintenance_delta: I256,
    /// Difference between margin balance and liquidation margin requirement
    pub liquidation_delta: I256,
    /// Difference between margin balance and dutch margin requirement
    pub dutch_delta: I256,
    /// Difference between margin balance and adl margin requirement
    pub adl_delta: I256,
    /// Difference between margin balance and initial buffer margin requirement (for backstop lps)
    pub initial_buffer_delta: I256,
    /// Information required to compute health of position in the context of adl liquidations
    pub liquidation_margin_requirement: U256,
}

/// auto exchange inputs
#[derive(Debug)]
pub struct TriggerAutoExchangeParams {
    pub account_id: u128,
    pub liquidator_account_id: u128,
    pub requested_quote_amount: U256,
    pub collateral: Address,
    pub in_collateral: Address,
}

#[derive(Debug)]
pub struct TryAggregateParams {
    pub require_success: bool,
    pub calls: Vec<Bytes>,
}

pub type StorkSignedPayload = OrderGatewayProxy::StorkSignedPayload;
pub type StorkPricePayload = OrderGatewayProxy::StorkPricePayload;
pub type EIP712Signature = OrderGatewayProxy::EIP712Signature;
