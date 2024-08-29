use alloy::sol;

// Codegen from ABI file to interact with the reya order gateway proxy contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    OrderGatewayProxy,
    "./transactions/abi/OrderGatewayProxy.json"
);

// Codegen from ABI file to interact with the reya passive perp instrument proxy contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    PassivePerpInstrumentProxy,
    "./transactions/abi/PassivePerpInstrumentProxy.json"
);

// Codegen from ABI file to interact with the reya core proxy contract
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    CoreProxy,
    "./transactions/abi/CoreProxy.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    // collection of all rcp errors from Core, PassivePerp and OrderGateway
    RpcErrors,
    "./transactions/abi/Errors.json"
);

// Codegen from ABI file to interact with the multicall3 contract
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    Multicall3,
    "./transactions/abi/Multicall3.json"
);

// Codegen from ABI file to interact with the oracle adapters contract
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    OracleAdaptersProxy,
    "./transactions/abi/OracleAdaptersProxy.json"
);

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
