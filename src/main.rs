use alloy::{
    //providers::{Provider, ProviderBuilder}, rpc::client::WsConnect, contract, 
    sol
    //, sol_types
};
use eyre;
use tokio;
//use futures_util::{future, StreamExt};
//use futures::task::Poll;



// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CoreProxy,
    "transactions/abi/CoreProxy.json"
);

#[tokio::main]
async fn main() -> eyre::Result<()> {
    println!("Hello, world!");
    //CoreProxy::getImplementationCall();
    
    eyre::Ok(())
}
