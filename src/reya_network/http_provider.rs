use crate::reya_network::data_types;
use alloy::{
    network::EthereumSigner,
    primitives::{Address, Bytes, I256, U256},
    providers::ProviderBuilder,
    signers::wallet::LocalWallet,
    sol,
};
use alloy_sol_types::SolValue;
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
 */
#[allow(dead_code)]
impl HttpProvider {
    ///
    pub fn new(http_url: &Url) -> HttpProvider {
        HttpProvider {
            url: http_url.clone(),
        }
    }

    ///
    pub async fn create_account(
        &self,
        signer: LocalWallet,
        account_owner_address: &Address,
    ) -> eyre::Result<Option<Address>> {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(self.url.clone());

        // core create account
        let core_proxy = CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider);
        let builder = core_proxy.createAccount(account_owner_address.clone());

        let receipt = builder.send().await?.get_receipt().await?;
        eyre::Ok(receipt.contract_address)
    }

    ///
    pub async fn execute(
        &self,
        signer: LocalWallet,
        account_id: u128,
        market_id: u128,
        exchange_id: u128,
        order_base: I256,        // side(+/- = buy/sell) + volume i256
        order_price_limit: U256, // order price u256
    ) -> eyre::Result<Option<Address>> {
        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(self.url.clone());

        println!(
            "Executing order, account={:?}, market={:?}, exchange:={:?}, base:{:?}, price={:?}",
            account_id, market_id, exchange_id, order_base, order_price_limit
        );

        // core create account
        let core_proxy = CoreProxy::new(data_types::CORE_CONTRACT_ADDRESS.parse()?, provider);

        let order_price_limit_bytes = order_price_limit.to_le_bytes::<32>();
        let order_base_bytes = order_base.to_le_bytes::<32>();
        let volume_price_bytes = vec![order_base_bytes, order_price_limit_bytes];

        // construct core proxy command struct
        let command_type = data_types::CommandType::MatchOrder;

        println!(
            "input bytes:{:?}",
            Bytes::from(volume_price_bytes.abi_encode())
        );

        let command = CoreProxy::Command {
            commandType: command_type as u8,                      //
            inputs: Bytes::from(volume_price_bytes.abi_encode()), //
            marketId: market_id,                                  //
            exchangeId: exchange_id,                              //
        };

        let builder = core_proxy.execute(account_id, vec![command]);
        let transaction_result = builder.send().await?;
        let receipt = transaction_result.get_receipt().await?;

        if receipt.inner.is_success() {
            println!("Execute logs:{:?}", receipt.inner.logs());
        }

        eyre::Ok(receipt.contract_address)
    }
}
