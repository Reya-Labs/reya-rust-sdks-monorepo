use crate::reya_network::data_types;
use alloy::{
    network::EthereumSigner,
    primitives::{address, Address, Bytes, B256, I256, U128, U256, U8},
    providers::{
        ext::{AnvilApi, TraceApi},
        Provider, ProviderBuilder,
    },
    rpc::types::{eth::TransactionRequest, trace::parity::TraceType},
    signers::wallet::LocalWallet,
    sol,
};
use alloy_sol_types::{sol_data::*, SolType, SolValue};

use eyre;

use url::Url;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CoreProxy,
    "transactions/abi/CoreProxy.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    rUSDProxy,
    "transactions/abi/rUsdProxy.json"
);

/**
 * HTTP Provider
 */
#[derive(Debug)]
pub struct HttpProvider {
    url: Url,
}

/**
 * HTTP Provider, implements several method to the CoreProxy
 * - create_account, create a new account
 * - execute, insert an order to match the LP limit order. Currently only a market order
 * - get_account_owner, gets the owners account
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
    ///    signers::wallet::LocalWallet,
    /// };
    ///
    /// let account_owner_address = address!("e7f6b70a36f4399e0853a311dc6699aba7343cc6");
    ///
    /// let signer: LocalWallet = private_key.parse().unwrap();
    ///
    /// let transaction_hash = http_provider.create_account(signer, &account_owner_address).await;
    ///
    /// println!("Created account, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn create_account(
        &self,
        signer: LocalWallet,
        account_owner_address: &Address,
    ) -> eyre::Result<B256> // return the transaction hash
    {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(self.url.clone());

        // core create account
        let core_proxy = CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider);
        let builder = core_proxy.createAccount(account_owner_address.clone());

        let receipt = builder.send().await?.get_receipt().await?;
        if receipt.inner.is_success() {
            println!("Create account, Transaction receipt:{:?}", receipt);
        }
        eyre::Ok(receipt.transaction_hash)
    }

    /// Execute, executes a market order on the reya network and returns the transaction hash on success
    ///
    /// Needs the following parameters:
    ///
    /// 1: the signer
    ///
    /// 2: account id
    ///
    /// 3: market_id, instrument symbol id for the reya network e.g.: 1=eth/rUSD, 2=btc/rUSD
    ///
    /// 4: exchange_id, 1=reya exchange
    ///
    /// 5: order base, side(+/- = buy/sell) + volume i256 * 10^18
    ///
    /// 6: order price, price * 10^18
    ///
    /// # Examples
    /// '''
    /// use crate::reya_network::http_provider;
    ///
    /// use alloy::{
    ///    primitives::{I256, U256},
    ///
    ///    signers::wallet::LocalWallet,
    /// };
    ///
    /// let account_owner_address = address!("e7f6b70a36f4399e0853a311dc6699aba7343cc6");
    ///
    /// let signer: LocalWallet = private_key.parse().unwrap();
    ///
    /// let transaction_hash = http_provider
    ///
    /// let market_id = 1u128;
    ///
    /// let exchange_id = 1u128;
    ///
    /// let order_base: I256 = "1".parse().unwrap();
    ///
    /// let order_price_limit: U256 = "1".parse().unwrap();
    ///
    /// let transaction_hash = http_provider.execute(signer, account_id, market_id, exchange_id, order_base, order_price_limit).await;
    ///
    /// println!("Execute match order, tx hash:{:?}", transaction_hash);
    ///  '''
    pub async fn execute(
        &self,
        signer: LocalWallet,
        account_id: u128,
        market_id: u128,
        exchange_id: u128,
        order_base: I256,        // side(+/- = buy/sell) + volume i256
        order_price_limit: U256, // order price limit u256
    ) -> eyre::Result<&str> // return the transaction hash
    {
        println!(
            "Executing order, account={:?}, market={:?}, exchange:={:?}, base:{:?}, price={:?}",
            account_id, market_id, exchange_id, order_base, order_price_limit
        );

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(self.url.clone());

        let core_proxy =
            CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider.clone());

        // generate encoded core command input

        let base_price_encoded = (order_base, order_price_limit).abi_encode();

        let counterparty_account_ids: Vec<u128> = vec![2u128];

        let base_price_counterparties_encoded =
            (counterparty_account_ids, base_price_encoded).abi_encode();

        // construct core proxy command struct
        let command_type = data_types::CommandType::MatchOrder;

        let command = CoreProxy::Command {
            commandType: command_type as u8,
            inputs: Bytes::from(base_price_counterparties_encoded),
            marketId: market_id,
            exchangeId: exchange_id,
        };

        let execute_call = core_proxy.execute(account_id, vec![command]);
        let calldata = execute_call.calldata().to_owned();
        println!("{:?}", calldata);

        eyre::Ok("Done")
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
    ///  let signer: LocalWallet = private_key.parse().unwrap();
    ///
    ///   let transaction_hash = http_provider.get_account_owner(signer, account_id).await;
    ///
    ///  println!("get account owner address, tx hash:{:?}", transaction_hash);
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
}
