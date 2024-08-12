use std::str::FromStr;

use alloy::primitives::U256;
use alloy_sol_types::SolCall;
use alloy_primitives::Bytes;
use alloy_primitives::Address;
use alloy_sol_types::SolValue;

use crate::data_types::Call;
use crate::data_types::Multicall3;
use crate::data_types::OracleAdaptersProxy;
use crate::data_types::MULTICALL_ADDRESS;
use crate::data_types::load_enviroment_config;

pub fn encode_multicall(require_success: bool, calls: Vec<Call>) -> Vec<u8> {

    let calldata = Multicall3::tryAggregateCall {
        requireSuccess: require_success, 
        calls: calls.iter().map(|x| Multicall3::Call { target: x.target, callData: Bytes::from(x.calldata.clone()) }).collect()
    };

    return calldata.abi_encode();
}

pub fn encode_strict_multicall(calls: Vec<Call>) -> Call {
    let calldata = encode_multicall(true, calls);

    return Call {
        target: MULTICALL_ADDRESS.parse().unwrap(),
        calldata,
    }
} 

pub fn encode_optional_multicall(calls: Vec<Call>) -> Call {
    let calldata = encode_multicall(false, calls);

    return Call {
        target: MULTICALL_ADDRESS.parse().unwrap(),
        calldata,
    }
} 

pub async fn multicall_oracle_prepend(call: Call) -> eyre::Result<Call> {
    let price_update_calls = multicall_oracle_append().await;
    let price_update_call = encode_optional_multicall(price_update_calls);

    return Ok(encode_strict_multicall(vec![
        price_update_call,
        call,
    ]));
}

pub struct StorkPricePayload {
    pub asset_pair_id: String, 
    pub timestamp: u64,
    pub price: String,
}

pub struct StorkSignedPayload {
    pub oracle_pub_key: String,
    pub price_payload: StorkPricePayload,
    pub r: String,
    pub s: String,
    pub v: u8,
}

pub async fn get_latest_stork_prices_api() -> Vec<StorkSignedPayload> {
    return vec![];
}

pub async fn get_latest_stork_prices_redis() -> Vec<StorkSignedPayload> {
    return vec![];
}

pub fn encode_stork_fulfill_oracle_query(signed_price_payload: &StorkSignedPayload) -> Vec<u8> {
    let oracle_pub_key = Address::from_str(signed_price_payload.oracle_pub_key.as_str()).unwrap();
    let asset_pair_id = signed_price_payload.price_payload.asset_pair_id.clone();
    let timestamp = U256::from(signed_price_payload.price_payload.timestamp / 1000000000);
    let price = U256::from_str(signed_price_payload.price_payload.price.as_str()).unwrap();
    let r: [u8; 32] = signed_price_payload.r.as_bytes().try_into().unwrap();
    let s: [u8; 32] = signed_price_payload.s.as_bytes().try_into().unwrap();
    let v: [u8; 1] = signed_price_payload.v.to_be_bytes();

    let signed_offchain_data = (oracle_pub_key, (asset_pair_id, timestamp, price), r, s, v).abi_encode();

    let calldata = OracleAdaptersProxy::fulfillOracleQueryCall{
        signedOffchainData: Bytes::from(signed_offchain_data),
    };

    return calldata.abi_encode();
}

pub async fn multicall_oracle_append() -> Vec<Call> {
    let stork_prices = &mut get_latest_stork_prices_redis().await;

    if stork_prices.len() == 0 {
        *stork_prices = get_latest_stork_prices_api().await;
    }

    let oracle_adapters_contract_address = load_enviroment_config().oracle_adapters_contract_address;

    return stork_prices.iter().map(|x| Call {
        target: Address::from_str(oracle_adapters_contract_address.as_str()).unwrap(),
        calldata: encode_stork_fulfill_oracle_query(x),
    }).collect();
}
