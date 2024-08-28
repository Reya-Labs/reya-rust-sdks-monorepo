use url::Url;

#[derive(Clone, Debug)]
pub enum NetworkEnv {
    Mainnet = 1729,
    Testnet = 89346162
}

#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub core: String,
    pub orders_gateway: String,
    pub perp: String,
    pub oracle_adapters: String,
    pub multicall3: String,
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub rpc_url: Url,
    pub contract_addresses: ContractAddresses,
    pub passive_pool_account_id: u128, // counter party account id (mainnet: 2, testnet: 4)
    pub exchange_id: u128,
}

pub fn get_network_config(network_env: NetworkEnv) -> NetworkConfig {
    match network_env {
        NetworkEnv::Mainnet => {
            return NetworkConfig {
                rpc_url: Url::parse("https://rpc.reya.network").unwrap(),
                contract_addresses: ContractAddresses {
                    core: "0xA763B6a5E09378434406C003daE6487FbbDc1a80".to_string(),
                    orders_gateway: "0xfc8c96bE87Da63CeCddBf54abFA7B13ee8044739".to_string(),
                    perp: "0x27E5cb712334e101B3c232eB0Be198baaa595F5F".to_string(),
                    oracle_adapters: "0x32edABC058C1207fE0Ec5F8557643c28E4FF379e".to_string(),
                    multicall3: "0xcA11bde05977b3631167028862bE2a173976CA11".to_string(),
                },
                passive_pool_account_id: 2u128,
                exchange_id: 1u128,
            }   
        },
        NetworkEnv::Testnet => {
            return NetworkConfig {
                rpc_url: Url::parse("https://rpc.reya-cronos.gelato.digital").unwrap(),
                contract_addresses: ContractAddresses {
                    core: "0xC6fB022962e1426F4e0ec9D2F8861c57926E9f72".to_string(),
                    orders_gateway: "0x5A0aC2f89E0BDeaFC5C549e354842210A3e87CA5".to_string(),
                    perp: "0x9EC177fed042eF2307928BE2F5CDbf663B20244B".to_string(),
                    oracle_adapters: "0xc501A2356703CD351703D68963c6F4136120f7CF".to_string(),
                    multicall3: "0xcA11bde05977b3631167028862bE2a173976CA11".to_string(),
                },
                passive_pool_account_id: 4u128,
                exchange_id: 1u128,
            }   
        },
    }
}