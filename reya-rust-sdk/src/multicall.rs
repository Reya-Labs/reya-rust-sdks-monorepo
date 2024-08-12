use std::str::FromStr;
use alloy_sol_types::{SolCall, SolValue};
use alloy_primitives::{Address, Bytes};
use crate::data_types::{Call, Multicall3, OracleAdaptersProxy, StorkSignedPayload, MULTICALL_ADDRESS, load_enviroment_config};
use tracing::*;

fn encode_multicall(require_success: bool, calls: Vec<Call>) -> Vec<u8> {

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

pub fn multicall_oracle_prepend(call: Call, stork_prices: &Vec<StorkSignedPayload>) -> Call {
    info!("AAAA");
    let price_update_calls = multicall_oracle_append(stork_prices);
    info!("BBBB");
    let price_update_call = encode_optional_multicall(price_update_calls);
    info!("CCCC");

    return encode_strict_multicall(vec![
        price_update_call,
        call,
    ]);
}

fn encode_stork_fulfill_oracle_query(signed_price_payload: &StorkSignedPayload) -> Vec<u8> {
    info!("FFFF");

    let oracle_pub_key = signed_price_payload.oracle_pub_key;
    let asset_pair_id = signed_price_payload.price_payload.asset_pair_id.clone();
    let timestamp = signed_price_payload.price_payload.timestamp;
    let price = signed_price_payload.price_payload.price;
    let r: [u8; 32] = signed_price_payload.r;
    let s: [u8; 32] = signed_price_payload.s;
    let v: [u8; 1] = signed_price_payload.v;

    let signed_offchain_data = (oracle_pub_key, (asset_pair_id, timestamp, price), r, s, v).abi_encode();

    let calldata = OracleAdaptersProxy::fulfillOracleQueryCall{
        signedOffchainData: Bytes::from(signed_offchain_data),
    };

    return calldata.abi_encode();
}

fn multicall_oracle_append(stork_prices: &Vec<StorkSignedPayload>) -> Vec<Call> {
    info!("DDDD");
    let oracle_adapters_contract_address = load_enviroment_config().oracle_adapters_contract_address;
    info!("EEEE");

    return stork_prices.iter().map(|x| Call {
        target: Address::from_str(oracle_adapters_contract_address.as_str()).unwrap(),
        calldata: encode_stork_fulfill_oracle_query(x),
    }).collect();
}
