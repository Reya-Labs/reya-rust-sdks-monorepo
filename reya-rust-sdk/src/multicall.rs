use crate::{
    data_types::{load_enviroment_config, Call, StorkSignedPayload, MULTICALL_ADDRESS},
    solidity::{Multicall3, OracleAdaptersProxy},
};
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolValue};
use eyre::{Result, WrapErr};
use std::str::FromStr;

fn encode_multicall(require_success: bool, calls: Vec<Call>) -> Vec<u8> {
    let calldata = Multicall3::tryAggregateCall {
        requireSuccess: require_success,
        calls: calls
            .iter()
            .map(|x| Multicall3::Call {
                target: x.target,
                callData: Bytes::from(x.calldata.clone()),
            })
            .collect(),
    };

    calldata.abi_encode()
}

pub fn encode_strict_multicall(calls: Vec<Call>) -> Result<Call> {
    let calldata = encode_multicall(true, calls);
    let target = Address::from_str(MULTICALL_ADDRESS)
        .wrap_err("MULTICALL_ADDRESS must be a valid address")?;

    Ok(Call { target, calldata })
}

pub fn encode_optional_multicall(calls: Vec<Call>) -> Result<Call> {
    let calldata = encode_multicall(false, calls);
    let target = Address::from_str(MULTICALL_ADDRESS)
        .wrap_err("MULTICALL_ADDRESS must be a valid address")?;

    Ok(Call { target, calldata })
}

pub fn multicall_oracle_prepend(
    call: Call,
    stork_prices: &Vec<StorkSignedPayload>,
) -> Result<Call> {
    let price_update_calls = multicall_oracle_append(stork_prices)?;
    let price_update_call = encode_optional_multicall(price_update_calls)?;

    encode_strict_multicall(vec![price_update_call, call])
}

fn encode_stork_fulfill_oracle_query(
    signed_price_payload: &StorkSignedPayload,
) -> Result<Vec<u8>> {
    let oracle_pub_key = signed_price_payload.oraclePubKey;
    let asset_pair_id = signed_price_payload.pricePayload.assetPairId.clone();
    let timestamp = signed_price_payload
        .pricePayload
        .timestamp
        .div_rem(U256::from(1_000_000_000u64))
        .0;
    let price = signed_price_payload.pricePayload.price;
    let r = signed_price_payload.r;
    let s = signed_price_payload.s;
    let v: U256 = signed_price_payload
        .v
        .to_string()
        .parse()
        .wrap_err("Stork signature recovery id must be a valid unsigned integer")?;

    let signed_offchain_data =
        (oracle_pub_key, (asset_pair_id, timestamp, price), r, s, v).abi_encode();

    let calldata = OracleAdaptersProxy::fulfillOracleQueryCall {
        signedOffchainData: Bytes::from(signed_offchain_data),
    };

    Ok(calldata.abi_encode())
}

fn multicall_oracle_append(stork_prices: &Vec<StorkSignedPayload>) -> Result<Vec<Call>> {
    let oracle_adapters_contract_address =
        load_enviroment_config()?.oracle_adapters_contract_address;
    let oracle_adapters_contract_address = Address::from_str(&oracle_adapters_contract_address)
        .wrap_err("ORACLE_ADAPTERS_CONTRACT_ADDRESS must be a valid address")?;

    stork_prices
        .iter()
        .map(|payload| {
            Ok(Call {
                target: oracle_adapters_contract_address,
                calldata: encode_stork_fulfill_oracle_query(payload)?,
            })
        })
        .collect()
}
