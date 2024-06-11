use alloy::{
    network::EthereumSigner,
    //sol_types,
    primitives::{address, Address, Bytes},
    providers::ProviderBuilder,
    //rpc::client::WsConnect,
    //signers::{k256::pkcs8::der::Encode, wallet::LocalWallet},
    signers::wallet::LocalWallet,
    sol,
};
use alloy_sol_types::SolValue;
use eyre;
use std::env;
use tokio;
use url::Url;

//use CoreProxy::new;

// Codegen from artifact.
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

#[repr(u8)]
#[derive(Debug)]
enum CommandType {
    Deposit = 0,
    Withdraw,
    DutchLiquidation,
    MatchOrder,
    TransferMarginAccount,
}

static CORE_CONTRACT_ADDRESS: &str = "0xA763B6a5E09378434406C003daE6487FbbDc1a80";

#[derive(Debug)]
struct HttpProvider {
    url: Url,
}

impl HttpProvider {
    pub fn new(http_url: &Url) -> HttpProvider {
        HttpProvider {
            url: http_url.clone(),
        }
    }

    pub async fn create_account(
        &self,
        private_key: &String,
        account_owner_address: &Address,
    ) -> eyre::Result<u128> {
        let signer: LocalWallet = private_key.parse().unwrap();

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(self.url.clone());

        // core create account
        let core_proxy = CoreProxy::new(CORE_CONTRACT_ADDRESS.parse()?, provider);
        let builder = core_proxy.createAccount(account_owner_address.clone());

        let account_return: CoreProxy::createAccountReturn = builder.call().await?;

        //let receipt = builder.send().await?.get_receipt().await?;

        eyre::Ok(account_return.accountId)
    }

    pub async fn execute(
        &self,
        private_key: &String,
        account_id: u128,
        market_id: u128,
        exchange_id: u128,
        order_base: u128,
        order_price_limit: u128,
    ) -> eyre::Result<Option<Address>> {
        let signer: LocalWallet = private_key.parse().unwrap();

        // create http provider
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(self.url.clone());

        // core create account
        let core_proxy = CoreProxy::new(CORE_CONTRACT_ADDRESS.parse()?, provider);

        let order_price_limit_bytes = order_price_limit.to_ne_bytes();
        let order_base_bytes = order_base.to_ne_bytes();
        let volume_price_bytes = vec![order_base_bytes, order_price_limit_bytes];

        // construct core proxy command struct
        let command_type = CommandType::MatchOrder;

        let command = CoreProxy::Command {
            commandType: command_type as u8,                      //
            inputs: Bytes::from(volume_price_bytes.abi_encode()), //
            marketId: market_id,                                  //
            exchangeId: exchange_id,                              //
        };

        let builder = core_proxy.execute(account_id, vec![command]);
        //let transaction_result : CoreProxy::executeReturn = builder.call().await?;
        //transaction_result.outputs[0] ; // collateral
        let transaction_result = builder.send().await?;
        let receipt = transaction_result.get_receipt().await?;

        if receipt.inner.is_success() {
            println!("Execute logs:{:?}", receipt.inner.logs());
            // this does not return the 'output' data from the execute call, not sure where to get it from :(
        }
        eyre::Ok(receipt.contract_address)

        //else {
        //    Option<Address>::new(address, provider)
        //    eyre::Error(())
        //}
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let url = Url::parse("https://rpc.reya.network")?;
    let http_provider: HttpProvider = HttpProvider::new(&url);

    let private_key = env::var("PRIVATE_KEY").unwrap();
    let account_owner_address = address!("f8f6b70a36f4398f0853a311dc6699aba8333cc1");

    // create account
    let account_id = http_provider
        .create_account(&private_key, &account_owner_address)
        .await;

    println!("Created account, account_id:{:?}", account_id);

    // execute order
    // todo get correct market and exchange id
    let account_id = 0u128;
    let market_id = 0u128;
    let exchange_id = 0u128;
    let order_base = 0u128;
    let order_price_limit = 0u128;
    let execution_result = http_provider
        .execute(
            &private_key,
            account_id,
            market_id,
            exchange_id,
            order_base,
            order_price_limit,
        )
        .await;
    println!(
        "Execute match order, contract address:{:?}",
        execution_result
    );

    // rusd view
    // let contract = rUSDProxy::new(
    //"0xa9F32a851B1800742e47725DA54a09A7Ef2556A3".parse()?,
    //     provider,
    // );

    // let rUSDProxy::totalSupplyReturn { _0 } = contract.totalSupply().call().await?;

    // println!("RUSD total supply is {_0}");

    // core view
    // let contract = coreProxy::new(
    //     "0xA763B6a5E09378434406C003daE6487FbbDc1a80".parse()?,
    //     provider,
    // );
    // let result = contract.getProtocolConfiguration().call().await?;

    Ok(())
}
