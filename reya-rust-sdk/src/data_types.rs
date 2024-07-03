use alloy::primitives::Address;
use alloy::primitives::I256;
use alloy::primitives::U256;
use alloy::sol;
use dotenv::dotenv;
use std::env;
use url::Url;

///
/// configuration struct for the sdk
///
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SdkConfig {
    pub order_gateway_contract_address: String,
    pub passiv_perp_instrument_address: String,
    pub private_key: String,
    pub rpc_url: Url,
}

pub fn load_enviroment_config() -> SdkConfig {
    dotenv().ok();

    let order_gateway_contract_address = env::var("ORDER_GATEWAY_CONTRACT_ADDRESS")
        .expect("Order gateway contract address must be set as environment variable")
        .to_lowercase();

    let passiv_perp_instrument_address = env::var("PASSIVE_PERP_INSTRUMENT_CONTRACT_ADDRESS")
        .expect("Passive perp instrument address must be set as environment variable")
        .to_lowercase();

    let private_key = env::var("PRIVATE_KEY")
        .expect("Private key must be set as environment variable")
        .to_lowercase();

    let rpc_url = Url::parse(
        env::var("RPC_URL")
            .expect("RPC Url must be set as environment variable")
            .to_lowercase()
            .as_str(),
    );

    let sdk_config = SdkConfig {
        order_gateway_contract_address: order_gateway_contract_address,
        passiv_perp_instrument_address: passiv_perp_instrument_address,
        private_key: private_key,
        rpc_url: rpc_url.unwrap(),
    };
    return sdk_config;
}

#[allow(dead_code)]
// exchanges
pub const REYA_EXCHANGE_ID: u128 = 1u128; //1=reya exchange

// markets
pub const ETH_MARKET_ID: u32 = 1u32; //1=reya eth market
pub const BTC_MARKET_ID: u32 = 2u32; //1=reya btc exchange

// Codegen from ABI file to interact with the reya core proxy contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OrderGatewayProxy,
    "./transactions/abi/OrderGatewayProxy.json"
);

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
}

/// order struct to execute orders in a batch
pub struct BatchOrder {
    pub account_id: u128,
    pub market_id: u128,
    pub exchange_id: u128,
    pub order_type: OrderType,
    /// side(+/- = buy/sell) + volume i256
    pub order_base: I256,
    /// stop price only set when order type = stop_loss
    pub stop_price: I256,
    pub price_limit: U256,
    pub signer_address: Address,
    pub order_nonce: U256,
    pub eip712_signature: OrderGatewayProxy::EIP712Signature,
    /// tells that the order is executed sucessfully on the chain, value is only used as return state
    pub is_executed_successfully: bool,
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
