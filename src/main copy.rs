//use alloy::{
//    //providers::{Provider, ProviderBuilder}, rpc::client::WsConnect, contract, 
//    sol
//    //, sol_types
//};

//use futures_util::{future, StreamExt};
//use futures::task::Poll;

use alloy_json_abi::JsonAbi;
//use eyre;
//use tokio;

// Codegen from ABI file to interact with the contract.
//sol!(
//    #[allow(missing_docs)]
//    CoreProxy,
//    "transactions/abi/CoreProxy.json"
//);

//#[tokio::main]
//async fn main() -> eyre::Result<()> {

fn main() {
    
    let path = "transactions/abi/CoreProxy.json";
    let json = std::fs::read_to_string(path).unwrap();
    //
    //println!("core proxy json:{:?}",json);

    let abi: JsonAbi = serde_json::from_str(&json).unwrap();
    for item in abi.items() {
        println!("{:?}", item);
    }
    
    //eyre::Ok(())
}
