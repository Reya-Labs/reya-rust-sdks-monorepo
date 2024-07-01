use alloy::primitives::Address;
use alloy::primitives::I256;
use alloy::primitives::U256;

#[allow(dead_code)]
pub static CORE_CONTRACT_ADDRESS: &str = "0xA763B6a5E09378434406C003daE6487FbbDc1a80";

pub const REYA_EXCHANGE_ID: u128 = 1u128; //1=reya exchange
pub const ETH_MARKET_ID: u32 = 1u32; //1=reya eth market
pub const BTC_MARKET_ID: u32 = 2u32; //1=reya btc exchange

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
    TakeProfit,
}

/// order struct to execute orders in a batch
#[derive(Debug)]
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
    pub signature: String,
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
