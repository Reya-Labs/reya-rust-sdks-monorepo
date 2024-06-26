use crate::data_types;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, B256, I256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::eth::Filter,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::SolValue;
use eyre;
use tracing::{debug, info, trace}; //, error, info, span, warn, Level};
use url::Url;

// Codegen from ABI file to interact with the reya core proxy contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CoreProxy,
    "./transactions/abi/CoreProxy.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    rUSDProxy,
    "./transactions/abi/rUsdProxy.json"
);

/**
 * HTTP Provider
 */
#[derive(Debug)]
pub struct HttpProvider {
    url: reqwest::Url,
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
    pub fn new(http_url: &Url) -> HttpProvider {
        HttpProvider {
            url: http_url.clone(),
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
    /// let signer: PrivateKeySigner = private_key.parse().unwrap();
    ///
    /// let transaction_hash = http_provider.create_account(signer, &account_owner_address).await;
    ///
    /// info!("Created account, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn create_account(
        &self,
        signer: PrivateKeySigner,
        account_owner_address: &Address,
    ) -> eyre::Result<B256> // return the transaction hash
    {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::from(signer))
            .on_http(self.url.clone());

        // core create account
        let core_proxy = CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider);
        let builder = core_proxy.createAccount(account_owner_address.clone());

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
    /// let signer: PrivateKeySigner = private_key.parse().unwrap();
    ///
    /// let transaction_hash = http_provider
    ///
    /// let market_id = 1u128;
    ///
    /// let exchange_id = 1u128;
    ///
    /// let order_base: I256 = "+35000000000000000".parse().unwrap();
    ///
    /// let order_price_limit: U256 = "4000000000000000000000".parse().unwrap();
    ///
    /// let transaction_hash = http_provider.execute(signer, account_id, market_id, exchange_id, order_base, order_price_limit).await;
    ///
    /// info!("Execute match order, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn execute(
        &self,
        signer: PrivateKeySigner,
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

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::from(signer))
            .on_http(self.url.clone());

        let core_proxy =
            CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider.clone());

        // generate encoded core command input

        let base_price_encoded = (order_base, order_price_limit).abi_encode_sequence();

        let counterparty_account_ids: Vec<u128> = vec![2u128];

        let base_price_counterparties_encoded =
            (counterparty_account_ids, base_price_encoded).abi_encode_sequence();

        // construct core proxy command struct
        let command_type = data_types::CommandType::MatchOrder;

        let command = CoreProxy::Command {
            commandType: command_type as u8,
            inputs: Bytes::from(base_price_counterparties_encoded),
            marketId: market_id,
            exchangeId: exchange_id,
        };

        let builder = core_proxy.execute(account_id, vec![command]);
        let transaction_result = builder.send().await?;
        let receipt = transaction_result.get_receipt().await?;

        if receipt.inner.is_success() {
            debug!("Execute receipt:{:?}", receipt);
        }

        eyre::Ok(receipt.transaction_hash)
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
            .on_http(self.url.clone());

        // core create account
        let core_proxy = CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider);

        // Call the contract, retrieve the account owner information.
        let CoreProxy::getAccountOwnerReturn { _0 } =
            core_proxy.getAccountOwner(account_id).call().await?;

        eyre::Ok(_0)
    }

    pub async fn get_transaction(
        &self,
        tx_hash: alloy_primitives::FixedBytes<32>,
    ) -> eyre::Result<Vec<u128>> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.url.clone());

        let transaction_response = provider.get_transaction_by_hash(tx_hash).await;

        info!("Transaction reponse:{:?}", Some(transaction_response));

        eyre::Ok(vec![])
    }

    async fn get_transaction_receipt(
        &self,
        _tx_hash: alloy_primitives::FixedBytes<32>,
    ) -> eyre::Result<Vec<u128>> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(self.url.clone());

        // filter is not complete if we want e.g. the tx_log details of the tx_has provided
        let filter = Filter::new().address(
            data_types::CORE_CONTRACT_ADDRESS
                .parse::<Address>()
                .unwrap(),
        );

        let transaction_receipt = provider.get_logs(&filter).await;

        info!("Transaction receipt:{:?}", Some(transaction_receipt));

        eyre::Ok(vec![])
    }
}
