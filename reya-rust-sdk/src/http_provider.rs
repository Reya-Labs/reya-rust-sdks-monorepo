use crate::data_types;
use crate::data_types::CoreProxy;
use crate::data_types::OrderGatewayProxy;
use crate::data_types::PassivePerpInstrumentProxy;
use crate::data_types::RpcErrors::RpcErrorsErrors;
use crate::data_types::TryAggregateParams;
use crate::data_types::PRICE_MULTIPLIER;
use crate::http_provider::CoreProxy::MulticallResult;
use alloy::{
    contract::Error,
    network::EthereumWallet,
    primitives::{aliases, Address, Bytes, B256, I256, U256},
    providers::{Provider, ProviderBuilder},
    rpc, // used for TransactionReceipt
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
    transports::RpcError,
};
use alloy_sol_types::{SolInterface, SolValue};
use eyre;
use eyre::{Report, WrapErr};
use hex::FromHex;
use rust_decimal::{prelude::*, Decimal};
use tracing::*;

#[derive(Debug)]
pub enum ReasonError {
    NonceAlreadyUsed,
    SignerNotAuthorized,
    InvalidSignature,
    OrderTypeNotFound,
    IncorrectStopLossDirection,
    ZeroStopLossOrderSize,
    MatchOrderOutputsLengthMismatch,
    HigherExecutionPrice,
    LowerExecutionPrice,
    UnknownError,
    DecodingError,
}

#[derive(Debug)]
pub enum AEReasonError {
    SameQuoteAndcollateral,
    ZeroAddress,
    SameAccountId,
    AccountNotFound,
    AccountPermissionDenied,
    CollateralPoolCollision,
    CollateralIsNotQuote,
    CollateralPoolNotFound,
    WithinBubbleCoverageNotExhausted,
    AccountNotEligibleForAutoExchange,
    CollateralCapExceeded,
    AccountBelowIM,
    NegativeAccountRealBalance,
    DecodingError,
    UnknownError,
}

#[derive(Debug)]
pub struct BatchExecuteOutput {
    pub market_id: u128,
    pub order_index: u32,
    pub execution_price: Decimal,
    pub order_nonce: u128,
    pub block_timestamp: aliases::BlockTimestamp,
    pub order_type: u8,
    // optional error details will only be set if an error occured
    pub reason_str: Option<String>,
    pub reason_error: Option<ReasonError>,
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    rUSDProxy,
    "./transactions/abi/rUsdProxy.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    /// batch execution input bytes structure definition
    struct BatchExecuteInputBytes
    {
        bool is_long;
        uint256 trigger_price;  // stop_price!
        uint256 price_limit;    // price limit is the slippage tolerance,we can set it to max uint or zero for now depending on the direction of the trade
    }

    struct ExecuteInputBytes
    {
        int256 order_base;  // price!
        uint256 price_limit;    // price limit is the slippage tolerance,we can set it to max uint or zero for now depending on the direction of the trade
    }
);
/**
 * HTTP Provider
 */
#[derive(Debug)]
pub struct HttpProvider {
    sdk_config: data_types::SdkConfig,
}

/**
 * HTTP Provider, implements several wrapper methods around Reya Core Proxy Contract On Reya Network
 * - create_account, create a new margin account
 * - execute, initiate a market order against the passive lp pool as a counterparty
 * - get_account_owner, gets the address which owns a given margin account based on its id
 */
#[allow(dead_code)]
impl HttpProvider {
    #[allow(rustdoc::bare_urls)]
    /// Construct new HTTP_provider
    /// First parameter is the url
    ///
    /// # Examples
    /// '''
    /// use crate::reya_network::http_provider;
    ///
    /// let url = Url::parse("https://rpc.reya.network");
    ///
    //  let http_provider: http_provider::HttpProvider = http_provider::HttpProvider::new(&url);
    /// '''
    pub fn new(sdk_config: &data_types::SdkConfig) -> HttpProvider {
        HttpProvider {
            sdk_config: sdk_config.clone(),
        }
    }

    /// CreateAccount, creates an account on the reya network and returns the transaction hash on success
    ///
    /// Needs the following parameters:
    ///
    /// 1: the signer
    ///
    /// 2: the account owner address
    ///
    /// # Examples
    /// '''
    /// use crate::reya_network::http_provider;
    ///
    /// use alloy::{
    ///    primitives::{I256, U256},
    ///
    ///    signers::wallet::PrivateKeySigner,
    /// };
    ///
    /// let account_owner_address = address!("e7f6b70a36f4399e0853a311dc6699aba7343cc6");
    ///
    /// let private_key:String=<your private key>;
    ///
    /// let transaction_hash = http_provider.create_account(private_key, &account_owner_address).await;
    ///
    /// info!("Created account, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn create_account(
        &self,
        private_key: &String,
        account_owner_address: &Address,
    ) -> eyre::Result<B256> // return the transaction hash
    {
        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        // core create account
        // todo: p1: use core proxy address (add to sdk config)
        let proxy = CoreProxy::new(
            self.sdk_config.order_gateway_contract_address.parse()?,
            provider,
        );
        let builder = proxy.createAccount(account_owner_address.clone());

        let receipt = builder.send().await?.get_receipt().await?;
        if receipt.inner.is_success() {
            debug!("Create account, Transaction receipt:{:?}", receipt);
        }
        eyre::Ok(receipt.transaction_hash)
    }

    /// Execute, executes a market order against passive lp pool on the reya network and returns the transaction hash on success
    ///
    /// Needs the following parameters:
    ///
    /// 1: signer,
    ///
    /// 2: account_id, the account id which identifies the margin account used to collateralise the derivative order
    ///
    /// 3: market_id, instrument symbol id for the reya network e.g.: 1=eth/rUSD, 2=btc/rUSD
    ///
    /// 4: exchange_id, 1=reya exchange
    ///
    /// 5: order_base, trade size in base token terms (e.g. eth for eth/rusd market) in WAD terms (scaled to 18 decimals) where sign determines direction
    ///
    /// 6: order_price_limit, if the order price limit is breached at the time of executing the order, it will get reverted on-chain
    ///
    /// # Examples
    /// '''
    /// use crate::reya_network::http_provider;
    ///
    /// use alloy::{
    ///    primitives::{I256, U256},
    ///
    ///    signers::wallet::PrivateKeySigner,
    /// };
    ///
    /// let account_owner_address = address!("e7f6b70a36f4399e0853a311dc6699aba7343cc6");
    ///
    /// let private_key:String=<your private key>;
    ///
    /// let market_id = 1u128;
    ///
    /// let exchange_id = 1u128;
    ///
    /// let order_base: I256 = "+35000000000000000".parse().unwrap();
    ///
    /// let order_price_limit: U256 = "4000000000000000000000".parse().unwrap();
    ///
    /// let transaction_hash = http_provider.execute(private_key, account_id, market_id, exchange_id, order_base, order_price_limit).await;
    ///
    /// info!("Execute match order, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn execute(
        &self,
        private_key: &String,
        account_id: u128,
        market_id: u128,
        exchange_id: u128,
        order_base: I256,        // side(+/- = buy/sell) + volume i256
        order_price_limit: U256, // order price limit u256
    ) -> eyre::Result<B256> // return the transaction hash
    {
        trace!(
            "Executing order, account={:?}, market={:?}, exchange:={:?}, base:{:?}, price={:?}",
            account_id,
            market_id,
            exchange_id,
            order_base,
            order_price_limit
        );

        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = OrderGatewayProxy::new(
            self.sdk_config.order_gateway_contract_address.parse()?,
            provider.clone(),
        );

        // generate encoded core command input
        let base_price_encoded = (order_base, order_price_limit).abi_encode_sequence();
        let counterparty_account_ids: Vec<u128> = vec![2u128]; // hardcode counter party id = 2
        let base_price_counterparties_encoded: Vec<u8> =
            (counterparty_account_ids, base_price_encoded).abi_encode_sequence();

        // construct core proxy command struct
        let command_type = data_types::CommandType::MatchOrder;

        let command = OrderGatewayProxy::Command {
            commandType: command_type as u8,
            inputs: Bytes::from(base_price_counterparties_encoded),
            marketId: market_id,
            exchangeId: exchange_id,
        };

        let builder = proxy.execute(account_id, vec![command]);
        let transaction_result = builder.send().await?;

        eyre::Ok(transaction_result.tx_hash().clone())
    }

    /// Executes a batch of orders and will return a transaction hash when the batch is executed.
    ///
    /// Incase transaction hash is return it does not mean all orders in the batch are successfully executed, these
    ///
    /// details are provided in the batch orders vector with the flag is_executed_successfully = true.
    ///
    /// Needs the following parameters:
    ///
    /// 1: signer,
    ///
    /// 2: batch_orders, vector with number of order to execute
    ///
    /// # Examples
    /// '''
    /// use crate::reya_network::http_provider;
    ///
    /// use alloy::{
    ///    primitives::{I256, U256},
    ///
    ///    signers::wallet::PrivateKeySigner,
    /// };
    ///
    /// let account_owner_address = address!("e7f6b70a36f4399e0853a311dc6699aba7343cc6");
    ///
    /// let private_key:String=<your private key>;
    ///
    /// let mut batch_orders:Vec<data_types::BatchOrder> = make_batch();
    ///
    /// let transaction_hash = http_provider.execute_batch(private_key, batch_orders).await;
    ///
    /// '''
    ///

    pub async fn execute_batch(
        &self,
        private_key: &String,
        batch_orders: &Vec<data_types::BatchOrder>,
    ) -> eyre::Result<B256> // return the transaction hash
    {
        trace!("Start Execute batch");

        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        let mut orders: Vec<OrderGatewayProxy::ConditionalOrderDetails> = vec![];
        let mut signatures: Vec<OrderGatewayProxy::EIP712Signature> = vec![];

        // add all order ans signatures to the batch vector
        for i in 0..batch_orders.len() {
            let batch_order: &data_types::BatchOrder = &batch_orders[i];

            trace!("Executing batch order:{:?}", batch_order);

            let mut encoded_input_bytes: Vec<u8> = Vec::new();
            let trigger_price: U256 = (batch_order.trigger_price * PRICE_MULTIPLIER)
                .trunc() // take only the integer part
                .to_string()
                .parse()
                .unwrap();

            if batch_order.order_type == data_types::OrderType::StopLoss
                || batch_order.order_type == data_types::OrderType::TakeProfit
            {
                // generate encoded core command for the input bytes of a stop_loss or take profit order
                // The input byte structure is:
                // {
                //     is_long,
                //     trigger_price, // stop_price!
                //     price_limit,   // price limit is the slippage tolerance,we can set it to max uint or zero for now depending on the direction of the trade
                // }// endcoded

                let batch_execute_input_bytes: BatchExecuteInputBytes = BatchExecuteInputBytes {
                    is_long: batch_order.is_long,
                    trigger_price: trigger_price,
                    price_limit: batch_order.price_limit,
                };

                encoded_input_bytes = batch_execute_input_bytes.abi_encode_sequence();

                trace!("SL/TP Encoding is_long={:?}, trigger price={:?}, price limit={:?}, encoded inputs={:?}", //
                batch_order.is_long, //
                trigger_price, //
                batch_order.price_limit, //
                encoded_input_bytes);
            } else if batch_order.order_type == data_types::OrderType::Limit {
                let order_base: I256 = (batch_order.order_base * PRICE_MULTIPLIER)
                    .trunc()
                    .to_string()
                    .parse()
                    .unwrap();

                let execute_input_bytes: ExecuteInputBytes = ExecuteInputBytes {
                    order_base: order_base,
                    price_limit: trigger_price,
                };
                encoded_input_bytes = execute_input_bytes.abi_encode_sequence();

                trace!("LO Encoding is_long={:?}, trigger_price={:?}, order_base={:?}, encoded_inputs={:?}", //
                batch_order.is_long, //
                trigger_price, //
                order_base, //
                encoded_input_bytes);
            }

            let counterparty_account_ids: Vec<u128> = vec![self.sdk_config.counter_party_id]; // counter party id = 2 for production, 4 for testnet

            let conditional_order_details = OrderGatewayProxy::ConditionalOrderDetails {
                accountId: batch_order.account_id,
                marketId: batch_order.market_id,
                exchangeId: batch_order.exchange_id,
                counterpartyAccountIds: counterparty_account_ids.clone(),
                orderType: batch_order.order_type as u8,
                inputs: Bytes::from(encoded_input_bytes),
                signer: batch_order.signer_address,
                nonce: batch_order.order_nonce,
            };
            trace!("Conditional order details={:?}", conditional_order_details);

            orders.push(conditional_order_details);

            signatures.push(batch_order.eip712_signature.clone());
        }

        trace!(
            "Execution batch orders={:?}, signatures={:?}",
            orders,
            signatures
        );

        let proxy = OrderGatewayProxy::new(
            self.sdk_config.order_gateway_contract_address.parse()?,
            provider.clone(),
        );

        let builder = proxy.batchExecute(orders, signatures);
        let new_gas_limit = (builder.estimate_gas().await? * 12u128) / 10u128;
        let b2 = builder.gas(new_gas_limit);

        let transaction_result = b2.send().await?;

        trace!("End Execute batch");

        eyre::Ok(transaction_result.tx_hash().clone())
    }

    /// Executes an auto exchange on the core proxy contract and returns the tx hash if succesful.
    ///
    /// In case it fails, it will attempt to decide the contract error. It will return the
    /// decoded message or an empty error if unable to decode.
    pub async fn trigger_auto_exchange(
        &self,
        private_key: &String,
        params: data_types::TriggerAutoExchangeParams,
    ) -> eyre::Result<B256> // return the transaction receipt
    {
        trace!("Start Trigger Auto-exchange");

        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        trace!(
            "Execution auto-exchange of account={:?}, collateral={:?}",
            params.account_id,
            params.collateral
        );

        let proxy = CoreProxy::new(
            self.sdk_config.core_proxy_address.parse()?,
            provider.clone(),
        );

        let inputs: CoreProxy::TriggerAutoExchangeInput = CoreProxy::TriggerAutoExchangeInput {
            accountId: params.account_id,
            liquidatorAccountId: params.liquidator_account_id,
            requestedQuoteAmount: params.requested_quote_amount,
            collateral: params.collateral,
            inCollateral: params.in_collateral,
        };

        let builder = proxy.triggerAutoExchange(inputs);

        match builder.send().await {
            Ok(transaction_result) => {
                trace!("End Trigger Auto-exchange");
                return eyre::Ok(transaction_result.tx_hash().clone());
            }
            Err(e) => match handle_rpc_error(e) {
                Some(error_string) => {
                    return Err(Report::msg(format!(
                        "Auto-exchange transaction reverted {:?}",
                        error_string
                    )));
                }
                None => {
                    return Err(Report::msg(format!("Auto-exchange transaction reverted")));
                }
            },
        }
    }

    /// gets the account of the owner that belongs to the provided account id and returns the transaction hash on success
    ///
    /// Needs the following parameters:
    ///
    /// 1: the signer
    ///
    /// 2: account id
    ///
    /// # Examples
    /// '''
    ///  let signer: PrivateKeySigner = private_key.parse().unwrap();
    ///
    ///   let transaction_hash = http_provider.get_account_owner(signer, account_id).await;
    ///
    ///  info!("get account owner address, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn get_account_owner(&self, account_id: u128) -> eyre::Result<Address> // return the account owner address
    {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.sdk_config.rpc_url.clone());

        // core create account
        let proxy = CoreProxy::new(self.sdk_config.core_proxy_address.parse()?, provider);

        // Call the contract, retrieve the account owner information.
        let CoreProxy::getAccountOwnerReturn { _0 } =
            proxy.getAccountOwner(account_id).call().await?;

        eyre::Ok(_0)
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: alloy_primitives::FixedBytes<32>,
    ) -> Option<rpc::types::TransactionReceipt> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.sdk_config.rpc_url.clone());

        let transaction_receipt_result = provider.get_transaction_receipt(tx_hash).await;

        match transaction_receipt_result {
            Ok(transaction_receipt) => {
                debug!(
                    "Transaction receipt:{:?}",
                    Some(transaction_receipt.clone())
                );
                return Some(transaction_receipt.clone()?);
            }
            Err(err) => {
                error!("{:?}", err);
                return None;
            }
        }
    }

    ///
    /// get the current pool price by market id and returns the instantaneous pool price
    ///
    pub async fn get_pool_price(&self, market_id: u128) -> eyre::Result<U256> {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = PassivePerpInstrumentProxy::new(
            self.sdk_config.passiv_perp_instrument_address.parse()?,
            provider,
        );

        // Call the contract and retrieve the instantaneous pool price.
        let PassivePerpInstrumentProxy::getInstantaneousPoolPriceReturn { _0 } =
            proxy.getInstantaneousPoolPrice(market_id).call().await?;

        eyre::Ok(_0)
    }

    pub async fn try_aggregate(
        &self,
        private_key: &String,
        params: data_types::TryAggregateParams,
    ) -> eyre::Result<B256> {
        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = CoreProxy::new(self.sdk_config.core_proxy_address.parse()?, provider);

        let builder = proxy.tryAggregate(params.require_success, params.calls);

        match builder.send().await {
            Ok(transaction_result) => {
                trace!("End Try Aggregate");
                return eyre::Ok(transaction_result.tx_hash().clone());
            }
            Err(e) => match handle_rpc_error(e) {
                Some(error_string) => {
                    return Err(Report::msg(format!(
                        "Try Aggregate transaction reverted {:?}",
                        error_string
                    )));
                }
                None => {
                    return Err(Report::msg(format!("Try Aggregate transaction reverted")));
                }
            },
        }
    }

    pub async fn try_aggregate_static_call(
        &self,
        sender_address: &String,
        params: TryAggregateParams,
    ) -> eyre::Result<Vec<MulticallResult>> {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = CoreProxy::new(self.sdk_config.core_proxy_address.parse()?, provider);

        let CoreProxy::tryAggregateReturn { result } = proxy
            .tryAggregate(params.require_success, params.calls)
            .from(sender_address.parse().unwrap())
            .call()
            .await?;

        eyre::Ok(result)
    }
}

///
/// decode the reason string to an Error
///
fn decode_reason(reason_bytes: Bytes) -> (String, ReasonError) {
    debug!("Reason string:{:?}", reason_bytes);

    match RpcErrorsErrors::abi_decode(&reason_bytes, true) {
        Ok(decoded_error) => match decoded_error {
            RpcErrorsErrors::NonceAlreadyUsed(nonce_already_used) => {
                error!("reason error={:?}", nonce_already_used);
                return (
                    String::from("NonceAlreadyUsed"),
                    ReasonError::NonceAlreadyUsed,
                );
            }
            RpcErrorsErrors::SignerNotAuthorized(signer_not_authorized) => {
                error!("reason error={:?}", signer_not_authorized);
                return (
                    String::from("SignerNotAuthorized"),
                    ReasonError::SignerNotAuthorized,
                );
            }
            RpcErrorsErrors::InvalidSignature(invalid_signature) => {
                error!("reason error={:?}", invalid_signature);
                return (
                    String::from("InvalidSignature"),
                    ReasonError::InvalidSignature,
                );
            }
            RpcErrorsErrors::OrderTypeNotFound(order_type_not_found) => {
                error!("reason error={:?}", order_type_not_found);
                return (
                    String::from("OrderTypeNotFound"),
                    ReasonError::OrderTypeNotFound,
                );
            }
            RpcErrorsErrors::IncorrectStopLossDirection(incorrect_stop_loss_direction) => {
                error!("reason error={:?}", incorrect_stop_loss_direction);
                return (
                    String::from("IncorrectStopLossDirection"),
                    ReasonError::IncorrectStopLossDirection,
                );
            }
            RpcErrorsErrors::ZeroStopLossOrderSize(zero_stop_loss_order_size) => {
                error!("reason error={:?}", zero_stop_loss_order_size);
                return (
                    String::from("ZeroStopLossOrderSize"),
                    ReasonError::ZeroStopLossOrderSize,
                );
            }
            RpcErrorsErrors::MatchOrderOutputsLengthMismatch(
                match_order_outputs_length_mis_match,
            ) => {
                error!("reason error={:?}", match_order_outputs_length_mis_match);
                return (
                    String::from("MatchOrderOutputsLengthMismatch"),
                    ReasonError::MatchOrderOutputsLengthMismatch,
                );
            }
            RpcErrorsErrors::HigherExecutionPrice(higher_execution_price) => {
                error!("reason error={:?}", higher_execution_price);
                return (
                    String::from("HigherExecutionPrice"),
                    ReasonError::HigherExecutionPrice,
                );
            }
            RpcErrorsErrors::LowerExecutionPrice(lower_execution_price) => {
                error!("reason error={:?}", lower_execution_price);
                return (
                    String::from("LowerExecutionPrice"),
                    ReasonError::LowerExecutionPrice,
                );
            }
            // all other errors are mapped to UnknownError
            _ => {
                info!("RPC error:{:?}", decoded_error);
                return (
                    format!("RPC error={:?}", decoded_error),
                    ReasonError::UnknownError,
                );
            }
        },
        Err(err) => {
            return (format!("Error={:?}", err), ReasonError::DecodingError);
        }
    }
}

///
/// decode the auto-exchange specific reason string to an Error
///
fn decode_auto_exchange_error(reason_bytes: Bytes) -> (String, AEReasonError) {
    match RpcErrorsErrors::abi_decode(&reason_bytes, true)
        .wrap_err("Failed to decode reason_string")
    {
        Ok(decoded_error) => match decoded_error {
            RpcErrorsErrors::SameQuoteAndcollateral(same_quote_collateral) => {
                error!("reason error={:?}", same_quote_collateral);
                return (
                    String::from("SameQuoteAndcollateral"),
                    AEReasonError::SameQuoteAndcollateral,
                );
            }
            RpcErrorsErrors::ZeroAddress(zero_address) => {
                error!("reason error={:?}", zero_address);
                return (String::from("ZeroAddress"), AEReasonError::ZeroAddress);
            }
            RpcErrorsErrors::SameAccountId(zero_address) => {
                error!("reason error={:?}", zero_address);
                return (String::from("SameAccountId"), AEReasonError::SameAccountId);
            }
            RpcErrorsErrors::AccountNotFound(account_not_found) => {
                error!("reason error={:?}", account_not_found);
                return (
                    String::from("AccountNotFound"),
                    AEReasonError::AccountNotFound,
                );
            }
            RpcErrorsErrors::AccountPermissionDenied(account_permission_denied) => {
                error!("reason error={:?}", account_permission_denied);
                return (
                    String::from("AccountPermissionDenied"),
                    AEReasonError::AccountPermissionDenied,
                );
            }
            RpcErrorsErrors::NegativeAccountRealBalance(negative_account_real_balance) => {
                error!("reason error={:?}", negative_account_real_balance);
                return (
                    String::from("NegativeAccountRealBalance"),
                    AEReasonError::NegativeAccountRealBalance,
                );
            }
            RpcErrorsErrors::CollateralPoolCollision(collateral_pool_collision) => {
                error!("reason error={:?}", collateral_pool_collision);
                return (
                    String::from("CollateralPoolCollision"),
                    AEReasonError::CollateralPoolCollision,
                );
            }
            RpcErrorsErrors::AccountBelowIM(account_below_im) => {
                error!("reason error={:?}", account_below_im);
                return (
                    String::from("AccountBelowIM"),
                    AEReasonError::AccountBelowIM,
                );
            }
            RpcErrorsErrors::CollateralIsNotQuote(collateral_is_not_quote) => {
                error!("reason error={:?}", collateral_is_not_quote);
                return (
                    String::from("CollateralIsNotQuote"),
                    AEReasonError::CollateralIsNotQuote,
                );
            }
            RpcErrorsErrors::CollateralPoolNotFound(collateral_pool_not_found) => {
                error!("reason error={:?}", collateral_pool_not_found);
                return (
                    String::from("CollateralPoolNotFound"),
                    AEReasonError::CollateralPoolNotFound,
                );
            }
            RpcErrorsErrors::WithinBubbleCoverageNotExhausted(within_bubble) => {
                error!("reason error={:?}", within_bubble);
                return (
                    String::from("WithinBubbleCoverageNotExhausted"),
                    AEReasonError::WithinBubbleCoverageNotExhausted,
                );
            }
            RpcErrorsErrors::AccountNotEligibleForAutoExchange(account_not_eligible) => {
                error!("reason error={:?}", account_not_eligible);
                return (
                    String::from("AccountNotEligibleForAutoExchange"),
                    AEReasonError::AccountNotEligibleForAutoExchange,
                );
            }
            RpcErrorsErrors::CollateralCapExceeded(collateral_cap_exceeded) => {
                error!("reason error={:?}", collateral_cap_exceeded);
                return (
                    String::from("CollateralCapExceeded"),
                    AEReasonError::CollateralCapExceeded,
                );
            }
            // all other errors are mapped to UnknownError
            _ => {
                info!("RPC error:{:?}", decoded_error);
                return (
                    format!("RPC error={:?}", decoded_error),
                    AEReasonError::UnknownError,
                );
            }
        },
        Err(err) => {
            return (format!("Error={:?}", err), AEReasonError::DecodingError);
        }
    }
}

///
/// parses a contract error and attempts to decode it into a known error.
/// does not return anything if decoding fails.
///
fn handle_rpc_error(e: Error) -> Option<String> {
    match e {
        Error::AbiError(revert_reason) => {
            error!("[Error decoding] ABI error: {:?}", revert_reason);
        }
        Error::TransportError(error) => {
            let RpcError::ErrorResp(e) = error else {
                error!("[Error decoding] Failed to match ErrorResp {:?}", error);
                return None;
            };
            match e.data {
                Some(payload) => {
                    let stt = payload.get().to_string();
                    let trimmed_str = stt.trim_matches('"');
                    let data_str = trimmed_str.trim_start_matches("0x");
                    // Convert the hex string to bytes
                    match Vec::from_hex(data_str) {
                        Ok(bytes) => {
                            let data = Bytes::from(bytes);
                            let (reason, _) = decode_auto_exchange_error(data);
                            info!("[Error decoding] Decoded error {:?}", reason);
                            return Some(reason);
                        }
                        Err(e) => {
                            error!(
                                "[Error decoding] Failed to get error bytes with error {:?}",
                                e
                            )
                        }
                    }
                }
                None => error!("[Error decoding] Failed to get error response"),
            }
        }
        _ => {
            error!("[Error decoding] Transaction failed: {:?}", e);
        }
    }
    return None;
}

/// Extract the batch execution output bytes, received from the transaction logs
///
/// The fn will return a vector with BatchExecuteOutputs that should match the number of orders in an executed batch
///
/// and will provide details on the executed order if successfull or what kind of error it has.
///
/// On success it will also provide details on the execution like, executed price, block time etc... see BatchExecuteOutput for details
pub fn extract_execute_batch_outputs(
    batch_execute_receipt: &rpc::types::TransactionReceipt,
) -> Vec<BatchExecuteOutput> {
    debug!("Extracting batch outputs");

    let logs = batch_execute_receipt.inner.logs();
    let mut result: Vec<BatchExecuteOutput> = Vec::new();

    for log in logs {
        let log_data = log.data();
        // topic0 is the hash of the signature of the event.
        let topic0 = log_data.topics()[0];

        match topic0 {
            // Match the `SuccessfulOrder(uint256,tuple,bytes,uint256)` event.
            OrderGatewayProxy::SuccessfulOrder::SIGNATURE_HASH => {
                let successful_order: OrderGatewayProxy::SuccessfulOrder =
                    log.log_decode().unwrap().inner.data;

                //decode and convert execution price to a Decimal
                let execution_price_decode =
                    U256::abi_decode(&successful_order.output.clone(), true).unwrap();
                let execution_price = Decimal::from_str(&execution_price_decode.to_string())
                    .unwrap()
                    / data_types::PRICE_MULTIPLIER;

                debug!(
                    "Successful order execution, execution price:{:?}, nonce={:?}",
                    execution_price, successful_order.order.nonce
                );

                let nonce: u128 = successful_order
                    .order
                    .nonce
                    .to_string()
                    .parse()
                    .unwrap_or(0u128);

                result.push(BatchExecuteOutput {
                    market_id: successful_order.order.marketId,
                    order_index: successful_order
                        .orderIndex
                        .to_string()
                        .parse()
                        .unwrap_or(0u32),

                    execution_price: execution_price,
                    order_nonce: nonce,
                    block_timestamp: successful_order
                        .blockTimestamp
                        .to_string()
                        .parse()
                        .unwrap_or(0u64),
                    order_type: successful_order.order.orderType,
                    // no errors here
                    reason_str: None,
                    reason_error: None,
                });
            }
            // failed order mesg parsing
            OrderGatewayProxy::FailedOrderMessage::SIGNATURE_HASH => {
                //
                let failed_order_message: OrderGatewayProxy::FailedOrderMessage =
                    log.log_decode().unwrap().inner.data;
                let nonce: u128 = failed_order_message
                    .order
                    .nonce
                    .to_string()
                    .parse()
                    .unwrap_or(0u128);

                result.push(BatchExecuteOutput {
                    market_id: failed_order_message.order.marketId,
                    order_index: failed_order_message
                        .orderIndex
                        .to_string()
                        .parse()
                        .unwrap_or(0u32),

                    execution_price: Decimal::from(0),
                    order_nonce: nonce,
                    block_timestamp: failed_order_message
                        .blockTimestamp
                        .to_string()
                        .parse()
                        .unwrap_or(0u64),
                    order_type: failed_order_message.order.orderType,
                    reason_str: Some(String::from("Failed")),
                    reason_error: Some(ReasonError::UnknownError),
                });
            }
            // failed order bytes parsing
            OrderGatewayProxy::FailedOrderBytes::SIGNATURE_HASH => {
                // decode the error reason string
                let failed_order_bytes: OrderGatewayProxy::FailedOrderBytes =
                    log.log_decode().unwrap().inner.data;

                debug!("failed order bytes struct={:?}", failed_order_bytes);

                let nonce: u128 = failed_order_bytes
                    .order
                    .nonce
                    .to_string()
                    .parse()
                    .unwrap_or(0u128);

                let (reason, reason_error) = decode_reason(failed_order_bytes.reason.clone());

                result.push(BatchExecuteOutput {
                    market_id: failed_order_bytes.order.marketId,
                    order_index: failed_order_bytes
                        .orderIndex
                        .to_string()
                        .parse()
                        .unwrap_or(0u32), //

                    execution_price: Decimal::from(0),
                    order_nonce: nonce,
                    order_type: failed_order_bytes.order.orderType,
                    block_timestamp: failed_order_bytes
                        .blockTimestamp
                        .to_string()
                        .parse()
                        .unwrap_or(0u64),

                    reason_str: Some(reason.clone()),
                    reason_error: Some(reason_error),
                });
            }
            OrderGatewayProxy::ConditionalOrderExecuted::SIGNATURE_HASH => {
                let conditional_order_executed: OrderGatewayProxy::ConditionalOrderExecuted =
                    log.log_decode().unwrap().inner.data;
                debug!(
                    "ConditionalOrderExecuted is executed sucessfully {:?}",
                    conditional_order_executed
                );
            }
            _ => { // unknown type here are ignored
            }
        }
    }

    return result;
}

#[cfg(test)]
mod tests {

    use super::*;
    use rust_decimal::Decimal;
    use rust_decimal_macros::dec;

    #[test]
    fn test_batch_execute_input_bytes_encoding() {
        println!("Testing batch execute input bytes encoding");
        let stop_price: Decimal = dec!(1_000);
        let trigger_price: U256 = (stop_price * PRICE_MULTIPLIER)
            .trunc() // take only the integer part
            .to_string()
            .parse()
            .unwrap();

        let price_limit: U256 = U256::ZERO;
        let is_long: bool = true;
        let batch_execut_input_bytes: BatchExecuteInputBytes = BatchExecuteInputBytes {
            is_long: is_long,
            trigger_price: trigger_price,
            price_limit: price_limit,
        };

        let encoded_input_bytes = batch_execut_input_bytes.abi_encode_sequence();
        println!("Input bytes:{:?}", encoded_input_bytes);

        // alternative way of encoding the input bytes
        let bytes = (is_long, trigger_price, price_limit).abi_encode_sequence();

        let mut encoded_inputs: Vec<u8> = Vec::new();
        encoded_inputs.clone_from(&bytes);
        assert_eq!(encoded_input_bytes, encoded_inputs);
    }
}
