use crate::data_types;
use crate::data_types::Call;
use crate::data_types::TryAggregateParams;
use crate::data_types::PRICE_MULTIPLIER;
use crate::multicall::multicall_oracle_prepend;
use crate::solidity::{
    BatchExecuteInputBytes, CoreProxy,
    CoreProxy::{MarginInfo, MulticallResult, TriggerAutoExchangeInput},
    ExecuteInputBytes, OrderGatewayProxy, PassivePerpInstrumentProxy, PassivePoolProxy, RpcErrors,
    RpcErrors::RpcErrorsErrors,
    RpcEvents,
};
use alloy::consensus::transaction;
use alloy::rpc::types::TransactionInput;
use alloy::rpc::types::TransactionRequest;
use alloy::{
    contract::Error,
    network::EthereumWallet,
    primitives::{aliases, Address, Bytes, B256, I256, U256},
    providers::{Provider, ProviderBuilder},
    rpc, // used for TransactionReceipt
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
    transports::RpcError,
};
use alloy_primitives::FixedBytes;
use alloy_primitives::TxKind;
use alloy_sol_types::SolCall;
use alloy_sol_types::{SolInterface, SolValue};
use eyre;
use eyre::{Report, WrapErr};
use hex::FromHex;
use rust_decimal::{prelude::*, Decimal};
use std::time::Duration;
use tracing::*;

#[derive(Debug)]
pub enum ReasonError {
    AccountBelowIM,
    HigherExecutionPrice,
    IncorrectOrderDirection,
    InvalidSignature,
    LowerExecutionPrice,
    NonceAlreadyUsed,
    OrderTypeNotFound,
    SignerNotAuthorized,
    StalePriceDetected,
    ZeroSlTpOrderSize,
    Unauthorized,
    UnacceptableOrderPrice,
    UnknownError,  // special error when the decoded error is not known
    DecodingError, // special error when the decoding of the error fails
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

    fn get_wallet_address(&self) -> Address {
        let signer = PrivateKeySigner::from_str(&self.sdk_config.private_key)
            .expect("should parse private key");

        return signer.address();
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

    pub async fn execute_batch(
        &self,
        private_key: &String,
        batch_orders: &Vec<data_types::BatchOrder>,
        stork_prices: &Vec<data_types::StorkSignedPayload>,
    ) -> eyre::Result<B256> // return the transaction hash
    {
        trace!("[Execute CO batch] Start");

        let mut orders: Vec<OrderGatewayProxy::ConditionalOrderDetails> = vec![];
        let mut signatures: Vec<OrderGatewayProxy::EIP712Signature> = vec![];

        // add all order ans signatures to the batch vector
        for i in 0..batch_orders.len() {
            let batch_order: &data_types::BatchOrder = &batch_orders[i];

            trace!(
                "[Execute CO batch] Processing order batch: {:?}",
                batch_order
            );

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

                trace!("[Execute CO batch] SL/TP Encoding: is_long={:?}, trigger price={:?}, price limit={:?}, encoded inputs={:?}",
                    batch_order.is_long,
                    trigger_price,
                    batch_order.price_limit,
                    encoded_input_bytes
                );
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

                trace!("[Execute CO batch] LO Encoding: is_long={:?}, trigger_price={:?}, order_base={:?}, encoded_inputs={:?}", //
                    batch_order.is_long, //
                    trigger_price, //
                    order_base, //
                    encoded_input_bytes
                );
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

            trace!(
                "[Execute CO batch] Conditional order details: {:?}",
                conditional_order_details
            );

            orders.push(conditional_order_details);
            signatures.push(batch_order.eip712_signature.clone());
        }

        trace!(
            "[Execute CO batch] Submitting order batch: orders={:?}, signatures={:?}",
            orders,
            signatures
        );

        let orders_gateway: Address = self.sdk_config.order_gateway_contract_address.parse()?;
        let batch_execute_call = OrderGatewayProxy::batchExecuteCall { orders, signatures };
        let batch_execute_calldata = batch_execute_call.abi_encode();

        let call = multicall_oracle_prepend(
            Call {
                target: orders_gateway,
                calldata: batch_execute_calldata,
            },
            stork_prices,
        );

        trace!("[Execute CO batch] Calling raw tx");
        return self
            .execute_tx(private_key, call.target, call.calldata)
            .await;
    }

    pub async fn execute_tx(
        &self,
        private_key: &String,
        target: Address,
        calldata: Vec<u8>,
    ) -> eyre::Result<B256> {
        trace!("[Executing raw tx] Start");

        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        let mut tx = TransactionRequest {
            to: Some(TxKind::Call(target)),
            input: TransactionInput {
                data: None,
                input: Some(Bytes::from(calldata)),
            },
            gas: Some(2_000_000_000),
            ..Default::default()
        };

        trace!("[Executing raw tx] Sending transaction");

        let transaction_result = provider.send_transaction(tx.clone()).await?;

        trace!("[Executing raw tx] Finish");

        eyre::Ok(transaction_result.tx_hash().clone())
    }

    /// Executes an auto exchange on the core proxy contract and returns the tx hash if succesful.
    ///
    /// In case it fails, it will attempt to decide the contract error. It will return the
    /// decoded message or an empty error if unable to decode.
    pub async fn trigger_auto_exchange(
        &self,
        params: data_types::TriggerAutoExchangeParams,
    ) -> eyre::Result<B256> // return the transaction receipt
    {
        trace!("Start Trigger Auto-exchange");

        let signer: PrivateKeySigner = self.sdk_config.private_key.parse().unwrap();
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
                error!(
                    "Failed to get tx receipt hash {:?} with error {:?}",
                    tx_hash, err
                );
                return None;
            }
        }
    }

    async fn poll_for_receipt(
        &self,
        tx_hash: alloy_primitives::FixedBytes<32>,
    ) -> Option<rpc::types::TransactionReceipt> {
        let polling_interval = Duration::from_secs(1);
        let mut run = 0;

        loop {
            match self.get_transaction_receipt(tx_hash).await {
                Some(receipt) => {
                    return Some(receipt);
                }
                None => {
                    info!("Transaction not yet confirmed. Waiting...");
                    tokio::time::sleep(polling_interval).await;
                    run = run + 1;
                    if (run >= 5) {
                        return None;
                    }
                }
            }
        }
    }

    ///
    /// gets the transaction receipt and decodes FailedCall events
    ///
    async fn decode_logs(&self, tx_hash: alloy_primitives::FixedBytes<32>) -> String {
        let tx_receipt_option = self.poll_for_receipt(tx_hash).await;
        match tx_receipt_option {
            Some(tx_receipt) => {
                let log_rec_option = tx_receipt.inner.as_receipt();
                match log_rec_option {
                    Some(log_rec) => {
                        let logs = log_rec.logs.clone();
                        let mut reason_string = String::from("");
                        for log in logs {
                            let topic = log.inner.data.topics()[0];
                            if topic == RpcEvents::FailedCall::SIGNATURE_HASH {
                                let failed_call: RpcEvents::FailedCall =
                                    log.log_decode().unwrap().inner.data;
                                let execution_price_decode =
                                    decode_auto_exchange_error(failed_call.returnData.clone());
                                reason_string.push_str(&String::from(execution_price_decode.0));
                            }
                        }
                        return reason_string;
                    }
                    None => {
                        warn!("Failed to get logs for tx hash {:?}", tx_hash);
                        return String::from("");
                    }
                }
            }
            None => {
                warn!("Failed to get receipt for tx hash {:?}", tx_hash);
                return String::from("");
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

    async fn try_aggregate(&self, params: data_types::TryAggregateParams) -> eyre::Result<B256> {
        let signer: PrivateKeySigner = self.sdk_config.private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = CoreProxy::new(self.sdk_config.core_proxy_address.parse()?, provider);

        let builder = proxy
            .tryAggregate(params.require_success, params.calls)
            .gas(2_000_000_000);

        match builder.send().await {
            Ok(transaction_result) => {
                trace!("End Try Aggregate");
                let hash = transaction_result.tx_hash().clone();

                transaction_result.get_receipt().await;

                return eyre::Ok(hash);
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

    async fn try_aggregate_static_call(
        &self,
        params: TryAggregateParams,
    ) -> eyre::Result<Vec<MulticallResult>> {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = CoreProxy::new(self.sdk_config.core_proxy_address.parse()?, provider);

        let CoreProxy::tryAggregateReturn { result } = proxy
            .tryAggregate(params.require_success, params.calls)
            .from(self.get_wallet_address())
            .call()
            .await?;

        eyre::Ok(result)
    }

    pub async fn get_accounts_max_quote_to_cover_in_auto_exchange(
        &self,
        batch_size: usize,
        account_ids: &Vec<u128>,
        quote_collateral: Address,
    ) -> eyre::Result<Vec<U256>> {
        let mut max_quote_to_cover_in_auto_exchange: Vec<U256> = Vec::new();

        for i in (0..account_ids.len()).step_by(batch_size) {
            let batch_account_ids =
                account_ids[i..std::cmp::min(i + batch_size, account_ids.len())].to_vec();
            let mut batch_calldata_array = Vec::new();
            for account_id in batch_account_ids.clone() {
                let data = CoreProxy::calculateMaxQuoteToCoverInAutoExchangeCall::new((
                    account_id,
                    quote_collateral,
                ));
                let calldata = alloy::hex::encode(
                    CoreProxy::calculateMaxQuoteToCoverInAutoExchangeCall::abi_encode(&data),
                );
                batch_calldata_array.push(calldata.parse().unwrap());
            }

            let multicall_results = self
                .try_aggregate_static_call(TryAggregateParams {
                    require_success: true,
                    calls: batch_calldata_array,
                })
                .await;

            match multicall_results {
                Ok(multicall_results) => {
                    for i in 0..batch_account_ids.len() {
                        let return_data = &multicall_results[i].returnData;
                        if return_data.len() > 0 {
                            let return_data_u256 = U256::abi_decode(return_data, true).unwrap();
                            max_quote_to_cover_in_auto_exchange.push(return_data_u256);
                        } else {
                            max_quote_to_cover_in_auto_exchange.push(U256::from(0));
                        }
                    }
                }
                Err(err) => {
                    return Err(Report::msg(format!(
                        "Failed to get max quote to cover in auto exchange, error={:?}",
                        err
                    )));
                }
            }
        }

        return eyre::Ok(max_quote_to_cover_in_auto_exchange);
    }

    pub async fn get_node_margin_infos(
        &self,
        batch_size: usize,
        account_ids: &Vec<u128>,
        token_address: Address,
    ) -> eyre::Result<Vec<MarginInfo>> {
        let mut node_margin_infos: Vec<MarginInfo> = Vec::new();

        for i in (0..account_ids.len()).step_by(batch_size) {
            let account_ids_batch =
                account_ids[i..std::cmp::min(i + batch_size, account_ids.len())].to_vec();

            let mut batch_calldata_array = Vec::new();
            for account_id in account_ids_batch {
                let data =
                    CoreProxy::getNodeMarginInfoCall::new((account_id, token_address.clone()));
                let calldata =
                    alloy::hex::encode(CoreProxy::getNodeMarginInfoCall::abi_encode(&data));
                batch_calldata_array.push(calldata.parse().unwrap());
            }

            let multicall_results = self
                .try_aggregate_static_call(TryAggregateParams {
                    require_success: true,
                    calls: batch_calldata_array,
                })
                .await;

            match multicall_results {
                Ok(results) => {
                    for result in results {
                        let node_margin_info =
                            MarginInfo::abi_decode(&result.returnData, true).unwrap();
                        node_margin_infos.push(node_margin_info);
                    }
                }
                Err(err) => {
                    return Err(Report::msg(format!(
                        "Failed to get node margin info, error={:?}",
                        err
                    )));
                }
            }
        }

        return eyre::Ok(node_margin_infos);
    }

    pub async fn get_token_margin_infos(
        &self,
        batch_size: usize,
        account_ids: &Vec<u128>,
        token_address: Address,
    ) -> eyre::Result<Vec<MarginInfo>> {
        let mut token_margin_infos: Vec<MarginInfo> = Vec::new();

        for i in (0..account_ids.len()).step_by(batch_size) {
            let account_ids_batch =
                account_ids[i..std::cmp::min(i + batch_size, account_ids.len())].to_vec();

            let mut batch_calldata_array = Vec::new();
            for account_id in account_ids_batch {
                let data =
                    CoreProxy::getTokenMarginInfoCall::new((account_id, token_address.clone()));
                let calldata =
                    alloy::hex::encode(CoreProxy::getTokenMarginInfoCall::abi_encode(&data));
                batch_calldata_array.push(calldata.parse().unwrap());
            }

            let multicall_results = self
                .try_aggregate_static_call(TryAggregateParams {
                    require_success: true,
                    calls: batch_calldata_array,
                })
                .await;

            match multicall_results {
                Ok(results) => {
                    for result in results {
                        let token_margin_info =
                            MarginInfo::abi_decode(&result.returnData, true).unwrap();
                        token_margin_infos.push(token_margin_info);
                    }
                }
                Err(err) => {
                    return Err(Report::msg(format!(
                        "Failed to get token margin info, error={:?}",
                        err
                    )));
                }
            }
        }

        return eyre::Ok(token_margin_infos);
    }

    pub async fn trigger_auto_exchange_for_accounts_and_collaterals(
        &self,
        batch_size: usize,
        liquidator_account_id: u128,
        ae_account_infos: Vec<(u128, U256)>,
        quote_collateral: Address,
        out_collaterals: Vec<Address>,
    ) -> eyre::Result<Vec<FixedBytes<32>>> {
        let mut transaction_hashes: Vec<FixedBytes<32>> = Vec::new();
        for i in (0..ae_account_infos.len()).step_by(batch_size) {
            let batch_account_infos = &ae_account_infos
                [i..std::cmp::min(i + batch_size, ae_account_infos.len())]
                .to_vec();

            let mut batch_calldata_array = Vec::new();
            for account_info in batch_account_infos {
                for out_collateral in out_collaterals.iter() {
                    let params = TriggerAutoExchangeInput {
                        accountId: account_info.0,
                        liquidatorAccountId: liquidator_account_id,
                        requestedQuoteAmount: account_info.1,
                        collateral: out_collateral.clone(),
                        inCollateral: quote_collateral,
                    };
                    let data = CoreProxy::triggerAutoExchangeCall::new((params,));
                    let calldata =
                        alloy::hex::encode(CoreProxy::triggerAutoExchangeCall::abi_encode(&data));
                    batch_calldata_array.push(calldata.parse().unwrap());
                }
            }

            let transaction_hash = self
                .try_aggregate(TryAggregateParams {
                    require_success: false,
                    calls: batch_calldata_array,
                })
                .await;

            match transaction_hash {
                Ok(tx_hash) => {
                    transaction_hashes.push(tx_hash);
                }
                Err(err) => {
                    let batch_account_ids: Vec<u128> =
                        batch_account_infos.iter().map(|x| x.0).collect();
                    return Err(Report::msg(format!(
                        "Failed to trigger AE for accounts {:?}, error={:?}",
                        batch_account_ids, err
                    )));
                }
            }
        }

        for tx_hash in &transaction_hashes {
            self.decode_logs(tx_hash.clone()).await; // logs error
        }
        return eyre::Ok(transaction_hashes);
    }

    pub async fn trigger_srusd_auto_exchange_for_account(
        &self,
        account_id: u128,
    ) -> eyre::Result<B256> {
        let signer: PrivateKeySigner = self.sdk_config.private_key.parse().unwrap();
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(self.sdk_config.rpc_url.clone());

        let proxy = PassivePoolProxy::new(
            self.sdk_config.passive_pool_proxy_address.parse()?,
            provider,
        );

        let builder = proxy
            .triggerStakedAssetAutoExchange(1, account_id)
            .gas(2_000_000_000);

        match builder.send().await {
            Ok(transaction_result) => {
                trace!("End Trigger SRUSD Auto-exchange");
                let hash = transaction_result.tx_hash().clone();

                transaction_result.get_receipt().await;

                return eyre::Ok(hash);
            }
            Err(e) => match handle_rpc_error(e) {
                Some(error_string) => {
                    return Err(Report::msg(format!(
                        "SRUSD Auto-exchange transaction reverted {:?}",
                        error_string
                    )));
                }
                None => {
                    return Err(Report::msg(format!(
                        "SRUSD Auto-exchange transaction reverted"
                    )));
                }
            },
        }
    }

    pub async fn trigger_srusd_auto_exchange_for_accounts(
        &self,
        account_ids: Vec<u128>,
    ) -> eyre::Result<Vec<FixedBytes<32>>> {
        let mut transaction_hashes: Vec<FixedBytes<32>> = Vec::new();
        for i in 0..account_ids.len() {
            let transaction_hash = self
                .trigger_srusd_auto_exchange_for_account(account_ids[i])
                .await;
            match transaction_hash {
                Ok(tx_hash) => {
                    transaction_hashes.push(tx_hash);
                }
                Err(err) => {
                    return Err(Report::msg(format!(
                        "Failed to trigger SRUSD AE for account {:?}, error={:?}",
                        account_ids[i], err
                    )));
                }
            }
        }

        for tx_hash in &transaction_hashes {
            self.decode_logs(tx_hash.clone()).await; // logs error
        }
        return eyre::Ok(transaction_hashes);
    }
}

///
/// decode the reason string to an Error
///
fn decode_reason(reason_bytes: Bytes) -> (String, ReasonError) {
    debug!("Reason string:{:?}", reason_bytes);

    match RpcErrorsErrors::abi_decode(&reason_bytes, true) {
        Ok(decoded_error) => match decoded_error {
            RpcErrorsErrors::AccountBelowIM(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (String::from("AccountBelowIM"), ReasonError::AccountBelowIM);
            }
            RpcErrorsErrors::HigherExecutionPrice(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("HigherExecutionPrice"),
                    ReasonError::HigherExecutionPrice,
                );
            }
            RpcErrorsErrors::IncorrectOrderDirection(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("IncorrectOrderDirection"),
                    ReasonError::IncorrectOrderDirection,
                );
            }
            RpcErrorsErrors::InvalidSignature(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("InvalidSignature"),
                    ReasonError::InvalidSignature,
                );
            }
            RpcErrorsErrors::LowerExecutionPrice(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("LowerExecutionPrice"),
                    ReasonError::LowerExecutionPrice,
                );
            }
            RpcErrorsErrors::NonceAlreadyUsed(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("NonceAlreadyUsed"),
                    ReasonError::NonceAlreadyUsed,
                );
            }
            RpcErrorsErrors::OrderTypeNotFound(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("OrderTypeNotFound"),
                    ReasonError::OrderTypeNotFound,
                );
            }
            RpcErrorsErrors::SignerNotAuthorized(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("SignerNotAuthorized"),
                    ReasonError::SignerNotAuthorized,
                );
            }
            RpcErrorsErrors::StalePriceDetected(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("StalePriceDetected"),
                    ReasonError::StalePriceDetected,
                );
            }
            RpcErrorsErrors::ZeroSlTpOrderSize(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("ZeroSlTpOrderSize"),
                    ReasonError::ZeroSlTpOrderSize,
                );
            }
            RpcErrorsErrors::Unauthorized(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (String::from("Unauthorized"), ReasonError::Unauthorized);
            }
            RpcErrorsErrors::UnacceptableOrderPrice(err) => {
                error!("[Decoding reason] Reason error = {:?}", err);
                return (
                    String::from("UnacceptableOrderPrice"),
                    ReasonError::UnacceptableOrderPrice,
                );
            }
            // all other errors are mapped to UnknownError
            _ => {
                info!("[Decoding reason] Unknown error: {:?}", decoded_error);
                return (
                    format!("RPC error = {:?}", decoded_error),
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
                None => error!("[Error decoding] Failed to get error response {:?}", e),
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
