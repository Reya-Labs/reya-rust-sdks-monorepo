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
    //#[allow(missing_docs)]
    //#[sol(rpc)]
    COREPROXY,
    #r"[
  {
    "type": "function",
    "name": "acceptOwnership",
    "inputs": [],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getImplementation",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "nominateNewOwner",
    "inputs": [
      {
        "name": "newNominatedOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "nominatedOwner",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "owner",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "renounceNomination",
    "inputs": [],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "simulateUpgradeTo",
    "inputs": [
      {
        "name": "newImplementation",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "upgradeTo",
    "inputs": [
      {
        "name": "newImplementation",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "OwnerChanged",
    "inputs": [
      {
        "name": "oldOwner",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "newOwner",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "OwnerNominated",
    "inputs": [
      {
        "name": "newOwner",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Upgraded",
    "inputs": [
      {
        "name": "self",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "implementation",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "ImplementationIsSterile",
    "inputs": [
      {
        "name": "implementation",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "NoChange",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotAContract",
    "inputs": [
      {
        "name": "contr",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "NotNominated",
    "inputs": [
      {
        "name": "addr",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "Unauthorized",
    "inputs": [
      {
        "name": "addr",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "UpgradeSimulationFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAddress",
    "inputs": []
  },
  {
    "type": "function",
    "name": "activateFirstMarketForAccount",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "announceBackstopLpWithdraw",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "createAccount",
    "inputs": [
      {
        "name": "accountOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getAccountBlockExposuresByMarket",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "int256[]",
        "internalType": "int256[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getAccountImMultiplier",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "UD60x18"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getAccountOwner",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getAccountPermissions",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "accountPerms",
        "type": "tuple[]",
        "internalType": "struct AccountPermissions[]",
        "components": [
          {
            "name": "user",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "permissions",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getActiveMarketsPerQuoteCollateral",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint128[]",
        "internalType": "uint128[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getCollateralInfo",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct CollateralInfo",
        "components": [
          {
            "name": "netDeposits",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "marginBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "realBalance",
            "type": "int256",
            "internalType": "int256"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getCollateralPoolIdOfAccount",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getLastCreatedAccountId",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getNodeMarginInfo",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct MarginInfo",
        "components": [
          {
            "name": "collateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marginBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "realBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "maintenanceDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "dutchDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "adlDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialBufferDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationMarginRequirement",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getTokenMarginInfo",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct MarginInfo",
        "components": [
          {
            "name": "collateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marginBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "realBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "maintenanceDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "dutchDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "adlDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialBufferDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationMarginRequirement",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getUsdNodeMarginInfo",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct MarginInfo",
        "components": [
          {
            "name": "collateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marginBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "realBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "maintenanceDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "dutchDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "adlDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialBufferDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationMarginRequirement",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "grantAccountPermission",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "hasAccountPermission",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isAuthorizedForAccount",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "target",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "notifyAccountTransfer",
    "inputs": [
      {
        "name": "from",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "renounceAccountPermission",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revokeAccountPermission",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setCustomImMultiplier",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "imMultiplier",
        "type": "uint256",
        "internalType": "UD60x18"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "AccountIsNotBackstopLp",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "backstopLpAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "blockTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountNotFound",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountPermissionDenied",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "target",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountPermissionNotGranted",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "ActiveAccount",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "BackstopLpCooldownPeriodAlreadyActive",
    "inputs": [
      {
        "name": "backstopLpAccountId",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "withdrawPeriodStartTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "blockTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "BackstopLpWithdrawPeriodAlreadyActive",
    "inputs": [
      {
        "name": "backstopLpAccountId",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "blockTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "CannotScheduleActiveTimer",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "blockTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "CollateralCapExceeded",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "collateralCap",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "poolBalance",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "CollateralIsNotQuote",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "CollateralNotConfigured",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "CollateralPoolNotFound",
    "inputs": [
      {
        "name": "id",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "ExpiredTimerSchedule",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "startTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "blockTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "FeatureUnavailable",
    "inputs": [
      {
        "name": "which",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "GlobalCollateralNotFound",
    "inputs": [
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "GlobalWithdrawLimitReached",
    "inputs": [
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidAccountPermission",
    "inputs": [
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidFilledExposures",
    "inputs": [
      {
        "name": "filledExposures",
        "type": "tuple[]",
        "internalType": "struct FilledExposure[]",
        "components": [
          {
            "name": "riskMatrixIndex",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "exposure",
            "type": "int256",
            "internalType": "int256"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "MarketNotFound",
    "inputs": [
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "OnlyAccountTokenProxy",
    "inputs": [
      {
        "name": "origin",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "OverflowInt256ToUint256",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OverflowUint256ToInt256",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OverflowUint256ToUint128",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OverflowUint8ToInt8",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PRBMath_MulDiv18_Overflow",
    "inputs": [
      {
        "name": "x",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "y",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "PRBMath_MulDiv_Overflow",
    "inputs": [
      {
        "name": "x",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "y",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "denominator",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "PRBMath_SD59x18_IntoUD60x18_Underflow",
    "inputs": [
      {
        "name": "x",
        "type": "int256",
        "internalType": "SD59x18"
      }
    ]
  },
  {
    "type": "error",
    "name": "PRBMath_SD59x18_Mul_InputTooSmall",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PRBMath_SD59x18_Mul_Overflow",
    "inputs": [
      {
        "name": "x",
        "type": "int256",
        "internalType": "SD59x18"
      },
      {
        "name": "y",
        "type": "int256",
        "internalType": "SD59x18"
      }
    ]
  },
  {
    "type": "error",
    "name": "PRBMath_UD60x18_Sqrt_Overflow",
    "inputs": [
      {
        "name": "x",
        "type": "uint256",
        "internalType": "UD60x18"
      }
    ]
  },
  {
    "type": "error",
    "name": "PositionOutOfBounds",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ValueAlreadyInSet",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ValueNotInSet",
    "inputs": []
  },
  {
    "type": "error",
    "name": "collateralWithdrawLimitReached",
    "inputs": [
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "windowStartTimestamp",
        "type": "uint32",
        "internalType": "uint32"
      }
    ]
  },
  {
    "type": "function",
    "name": "approve",
    "inputs": [
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "balanceOf",
    "inputs": [
      {
        "name": "holder",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "burn",
    "inputs": [
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getApproved",
    "inputs": [
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "tokenName",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "tokenSymbol",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "uri",
        "type": "string",
        "internalType": "string"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "isApprovedForAll",
    "inputs": [
      {
        "name": "holder",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "operator",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isInitialized",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "mint",
    "inputs": [
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "name",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ownerOf",
    "inputs": [
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "safeMint",
    "inputs": [
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "safeTransferFrom",
    "inputs": [
      {
        "name": "from",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "safeTransferFrom",
    "inputs": [
      {
        "name": "from",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setAllowance",
    "inputs": [
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "spender",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setApprovalForAll",
    "inputs": [
      {
        "name": "operator",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "approved",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "supportsInterface",
    "inputs": [
      {
        "name": "interfaceId",
        "type": "bytes4",
        "internalType": "bytes4"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "symbol",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "tokenByIndex",
    "inputs": [
      {
        "name": "index",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "tokenOfOwnerByIndex",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "index",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "tokenURI",
    "inputs": [
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "string",
        "internalType": "string"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "totalSupply",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "transferFrom",
    "inputs": [
      {
        "name": "from",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "Approval",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "approved",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "indexed": true,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "ApprovalForAll",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "operator",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "approved",
        "type": "bool",
        "indexed": false,
        "internalType": "bool"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Transfer",
    "inputs": [
      {
        "name": "from",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "to",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "tokenId",
        "type": "uint256",
        "indexed": true,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "AlreadyInitialized",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CannotSelfApprove",
    "inputs": [
      {
        "name": "addr",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "IndexOverrun",
    "inputs": [
      {
        "name": "requestedIndex",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "length",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidOwner",
    "inputs": [
      {
        "name": "addr",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidParameter",
    "inputs": [
      {
        "name": "parameter",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "reason",
        "type": "string",
        "internalType": "string"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidTransferRecipient",
    "inputs": [
      {
        "name": "addr",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "TokenAlreadyMinted",
    "inputs": [
      {
        "name": "id",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "TokenDoesNotExist",
    "inputs": [
      {
        "name": "id",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "name": "getAssociatedSystem",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "addr",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "kind",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initOrUpgradeNft",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "name",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "symbol",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "uri",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "impl",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "AssociatedSystemSet",
    "inputs": [
      {
        "name": "kind",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "proxy",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      },
      {
        "name": "impl",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "MismatchAssociatedSystemKind",
    "inputs": [
      {
        "name": "expected",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "actual",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "MissingAssociatedSystem",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "function",
    "name": "configureAutoExchange",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct AutoExchangeConfig",
        "components": [
          {
            "name": "totalAutoExchangeThresholdInUSD",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "negativeCollateralBalancesMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteBufferPercentage",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getAutoExchangeConfiguration",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct AutoExchangeConfig",
        "components": [
          {
            "name": "totalAutoExchangeThresholdInUSD",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "negativeCollateralBalancesMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteBufferPercentage",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "error",
    "name": "CollateralPoolUnauthorized",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "InactiveCollateralPool",
    "inputs": [
      {
        "name": "id",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidAutoExchangeConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct AutoExchangeConfig",
        "components": [
          {
            "name": "totalAutoExchangeThresholdInUSD",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "negativeCollateralBalancesMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteBufferPercentage",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "calculateAvailableCollateralToBeAutoExchanged",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "outCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "calculateMaxQuoteToCoverInAutoExchange",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "inCollateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isCollateralInBubbleExhausted",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "inCollateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "triggerAutoExchange",
    "inputs": [
      {
        "name": "input",
        "type": "tuple",
        "internalType": "struct TriggerAutoExchangeInput",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidatorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "requestedQuoteAmount",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "collateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "inCollateral",
            "type": "address",
            "internalType": "address"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct AutoExchangeAmounts",
        "components": [
          {
            "name": "collateralAmountToLiquidator",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "quoteAmountToIF",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "quoteAmountToAccount",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "AccountBelowIM",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountNotEligibleForAutoExchange",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "inCollateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "CollateralPoolCollision",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "counterpartyCollateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "NegativeAccountRealBalance",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "realBalance",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "SameAccountId",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "SameQuoteAndcollateral",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "inCollateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "WithinBubbleCoverageNotExhausted",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "inCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "name": "getCollateralConfig",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateralAddress",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct CollateralConfig",
        "components": [
          {
            "name": "depositingEnabled",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "cap",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawalWindowSize",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "withdrawalTvlPercentageLimit",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeThreshold",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "autoExchangeInsuranceFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeDustThreshold",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidSubmissionFee",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct ParentCollateralConfig",
        "components": [
          {
            "name": "collateralAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "priceHaircut",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeDiscount",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "oracleNodeId",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      },
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct CachedCollateralConfig",
        "components": [
          {
            "name": "collateralPoolId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "collateralAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "windowWithdrawals",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "windowStartTimestamp",
            "type": "uint32",
            "internalType": "uint32"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getGlobalCollateralConfig",
    "inputs": [
      {
        "name": "collateralAddress",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct GlobalCollateralConfig",
        "components": [
          {
            "name": "collateralAdapter",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "withdrawalWindowSize",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "withdrawalTvlPercentageLimit",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      },
      {
        "name": "cachedConfig",
        "type": "tuple",
        "internalType": "struct GlobalCachedCollateralConfig",
        "components": [
          {
            "name": "collateralAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "collateralDecimals",
            "type": "uint8",
            "internalType": "uint8"
          },
          {
            "name": "windowWithdrawals",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "windowStartTimestamp",
            "type": "uint32",
            "internalType": "uint32"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "setCollateralConfig",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateralAddress",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "baseConfig",
        "type": "tuple",
        "internalType": "struct CollateralConfig",
        "components": [
          {
            "name": "depositingEnabled",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "cap",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawalWindowSize",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "withdrawalTvlPercentageLimit",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeThreshold",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "autoExchangeInsuranceFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeDustThreshold",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidSubmissionFee",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "parentConfig",
        "type": "tuple",
        "internalType": "struct ParentCollateralConfig",
        "components": [
          {
            "name": "collateralAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "priceHaircut",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeDiscount",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "oracleNodeId",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setGlobalCollateralConfig",
    "inputs": [
      {
        "name": "collateralAddress",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct GlobalCollateralConfig",
        "components": [
          {
            "name": "collateralAdapter",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "withdrawalWindowSize",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "withdrawalTvlPercentageLimit",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "CollateralLimitBreached",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "numberOfCollaterals",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "maxCollaterals",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "IncorrectCollateralAdapter",
    "inputs": [
      {
        "name": "collateralAdapterAddress",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidCollateralBaseConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct CollateralConfig",
        "components": [
          {
            "name": "depositingEnabled",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "cap",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawalWindowSize",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "withdrawalTvlPercentageLimit",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeThreshold",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "autoExchangeInsuranceFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeDustThreshold",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidSubmissionFee",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidCollateralParentConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct ParentCollateralConfig",
        "components": [
          {
            "name": "collateralAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "priceHaircut",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "autoExchangeDiscount",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "oracleNodeId",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidGlobalCollateralConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct GlobalCollateralConfig",
        "components": [
          {
            "name": "collateralAdapter",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "withdrawalWindowSize",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "withdrawalTvlPercentageLimit",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidNewParentCollateral",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "newParentCollateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "QuoteCollateralCannotBecomeSupportingCollateral",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "name": "getCollateralPoolBalance",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getCollateralPoolLimits",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct LimitConfig",
        "components": [
          {
            "name": "maxMarkets",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxCollaterals",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getCollateralPoolOwner",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getLastCreatedRiskBlockId",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "grantConfigurationPermission",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "hasConfigurationPermission",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "mergeCollateralPools",
    "inputs": [
      {
        "name": "parentCollateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "childCollateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revokeConfigurationPermission",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "permission",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setCollateralPoolLimits",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "limits",
        "type": "tuple",
        "internalType": "struct LimitConfig",
        "components": [
          {
            "name": "maxMarkets",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxCollaterals",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "transferCollateralPoolOwnership",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "newOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "CannotMergePoolWithItself",
    "inputs": [
      {
        "name": "id",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "MarketLimitBreached",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "numberOfMarkets",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "maxMarkets",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "name": "deposit",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "FailedTransfer",
    "inputs": [
      {
        "name": "from",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "value",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InsufficientAllowance",
    "inputs": [
      {
        "name": "required",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "existing",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "ZeroDeposit",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "name": "getLastCreatedExchangeId",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "registerExchange",
    "inputs": [
      {
        "name": "exchangeFeeCollectorAccountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "exchangeId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "ExchangeNotFound",
    "inputs": [
      {
        "name": "exchangeId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "OnlyExchangePassOwner",
    "inputs": []
  },
  {
    "type": "function",
    "name": "execute",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "commands",
        "type": "tuple[]",
        "internalType": "struct Command[]",
        "components": [
          {
            "name": "commandType",
            "type": "uint8",
            "internalType": "enum CommandType"
          },
          {
            "name": "inputs",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "marketId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "exchangeId",
            "type": "uint128",
            "internalType": "uint128"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "outputs",
        "type": "bytes[]",
        "internalType": "bytes[]"
      },
      {
        "name": "usdNodeMarginInfo",
        "type": "tuple",
        "internalType": "struct MarginInfo",
        "components": [
          {
            "name": "collateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marginBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "realBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "maintenanceDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "dutchDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "adlDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialBufferDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationMarginRequirement",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "executeBySig",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "commands",
        "type": "tuple[]",
        "internalType": "struct Command[]",
        "components": [
          {
            "name": "commandType",
            "type": "uint8",
            "internalType": "enum CommandType"
          },
          {
            "name": "inputs",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "marketId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "exchangeId",
            "type": "uint128",
            "internalType": "uint128"
          }
        ]
      },
      {
        "name": "sig",
        "type": "tuple",
        "internalType": "struct EIP712Signature",
        "components": [
          {
            "name": "v",
            "type": "uint8",
            "internalType": "uint8"
          },
          {
            "name": "r",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "s",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "deadline",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      },
      {
        "name": "extraSignatureData",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "outputs",
        "type": "bytes[]",
        "internalType": "bytes[]"
      },
      {
        "name": "usdNodeMarginInfo",
        "type": "tuple",
        "internalType": "struct MarginInfo",
        "components": [
          {
            "name": "collateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marginBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "realBalance",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "maintenanceDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "dutchDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "adlDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "initialBufferDelta",
            "type": "int256",
            "internalType": "int256"
          },
          {
            "name": "liquidationMarginRequirement",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "BackstopLpWithdrawPeriodInactive",
    "inputs": [
      {
        "name": "backstopLpAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "blockTimestamp",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidCommandType",
    "inputs": [
      {
        "name": "commandType",
        "type": "uint8",
        "internalType": "enum CommandType"
      }
    ]
  },
  {
    "type": "error",
    "name": "SignatureExpired",
    "inputs": []
  },
  {
    "type": "error",
    "name": "SignatureInvalid",
    "inputs": []
  },
  {
    "type": "error",
    "name": "TransferFromAndToSameAccount",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "ZeroTransfer",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "ZeroWithdraw",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "collateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "name": "addToFeatureFlagAllowlist",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "account",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getDeniers",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address[]",
        "internalType": "address[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getFeatureFlagAllowAll",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getFeatureFlagAllowlist",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address[]",
        "internalType": "address[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getFeatureFlagDenyAll",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isFeatureAllowed",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "account",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "removeFromFeatureFlagAllowlist",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "account",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setDeniers",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "deniers",
        "type": "address[]",
        "internalType": "address[]"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setFeatureFlagAllowAll",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "allowAll",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setFeatureFlagDenyAll",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "denyAll",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "FeatureFlagAllowAllSet",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "allowAll",
        "type": "bool",
        "indexed": false,
        "internalType": "bool"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "FeatureFlagAllowlistAdded",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "account",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "FeatureFlagAllowlistRemoved",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "account",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "FeatureFlagDeniersReset",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "deniers",
        "type": "address[]",
        "indexed": false,
        "internalType": "address[]"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "FeatureFlagDenyAllSet",
    "inputs": [
      {
        "name": "feature",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "denyAll",
        "type": "bool",
        "indexed": false,
        "internalType": "bool"
      }
    ],
    "anonymous": false
  },
  {
    "type": "function",
    "name": "getCollateralPoolIdOfMarket",
    "inputs": [
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getLastCreatedMarketId",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "registerMarket",
    "inputs": [
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "name",
        "type": "string",
        "internalType": "string"
      }
    ],
    "outputs": [
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "setRiskBlockId",
    "inputs": [
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "riskBlockId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "IncorrectMarketInterface",
    "inputs": [
      {
        "name": "market",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "InstrumentNotFound",
    "inputs": [
      {
        "name": "instrumentAddress",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "MissingRiskBlock",
    "inputs": [
      {
        "name": "riskBlockId",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "ZeroQuoteCollateralAddress",
    "inputs": []
  },
  {
    "type": "function",
    "name": "isInstrumentRegistered",
    "inputs": [
      {
        "name": "instrumentAddress",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "isRegisteredFlag",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "setInstrumentRegistrationFlag",
    "inputs": [
      {
        "name": "instrumentAddress",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "isRegistered",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "configureCollateralPoolInsuranceFund",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct InsuranceFundConfig",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidationFee",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getCollateralPoolInsuranceFundConfiguration",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct InsuranceFundConfig",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidationFee",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "error",
    "name": "InvalidInsuranceFundConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct InsuranceFundConfig",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidationFee",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "configureProtocol",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct ProtocolConfiguration.Data",
        "components": [
          {
            "name": "oracleManagerAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "exchangePassNFTAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "feeCollectorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getProtocolConfiguration",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct ProtocolConfiguration.Data",
        "components": [
          {
            "name": "oracleManagerAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "exchangePassNFTAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "feeCollectorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          }
        ]
      }
    ],
    "stateMutability": "pure"
  },
  {
    "type": "function",
    "name": "configureLiquidation",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct LiquidationConfig",
        "components": [
          {
            "name": "bidKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "queueDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxOrdersInBid",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxBidsInQueue",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidScoreWeight",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "backstopKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "adlExecutionKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dDutchMin",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dMax",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "configureRiskMultipliers",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct RiskMultipliers",
        "components": [
          {
            "name": "imMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "mmrMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dutchMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "adlMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "imBufferMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "createRiskMatrix",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "values",
        "type": "int64[][]",
        "internalType": "SD1x18[][]"
      }
    ],
    "outputs": [
      {
        "name": "blockId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "getBackstopLPConfig",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct BackstopLPConfig",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidationFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "minFreeCollateralThresholdInUSD",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawCooldownDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getLiquidationConfig",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct LiquidationConfig",
        "components": [
          {
            "name": "bidKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "queueDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxOrdersInBid",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxBidsInQueue",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidScoreWeight",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "backstopKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "adlExecutionKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dDutchMin",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dMax",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getRiskBlockMatrix",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "blockId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "int64[][]",
        "internalType": "SD1x18[][]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getRiskBlockMatrixByMarket",
    "inputs": [
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "int64[][]",
        "internalType": "SD1x18[][]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getRiskMultipliers",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct RiskMultipliers",
        "components": [
          {
            "name": "imMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "mmrMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dutchMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "adlMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "imBufferMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "setBackstopLPConfig",
    "inputs": [
      {
        "name": "collateralPoolId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct BackstopLPConfig",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidationFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "minFreeCollateralThresholdInUSD",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawCooldownDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "InvalidBackstopConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct BackstopLPConfig",
        "components": [
          {
            "name": "accountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "liquidationFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "minFreeCollateralThresholdInUSD",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawCooldownDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "withdrawDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidBackstopLPAccount",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidLiquidationConfiguration",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct LiquidationConfig",
        "components": [
          {
            "name": "bidKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "queueDurationInSeconds",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxOrdersInBid",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxBidsInQueue",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidScoreWeight",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "backstopKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "adlExecutionKeeperFee",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dDutchMin",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dMax",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidRiskMatrix",
    "inputs": [
      {
        "name": "riskMatrix",
        "type": "int64[][]",
        "internalType": "SD1x18[][]"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidRiskMultipliers",
    "inputs": [
      {
        "name": "config",
        "type": "tuple",
        "internalType": "struct RiskMultipliers",
        "components": [
          {
            "name": "imMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "mmrMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "dutchMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "adlMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "imBufferMultiplier",
            "type": "uint256",
            "internalType": "UD60x18"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "PRBMath_SD59x18_Abs_MinSD59x18",
    "inputs": []
  },
  {
    "type": "function",
    "name": "executeBackstopLiquidation",
    "inputs": [
      {
        "name": "liquidatableAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "keeperAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "backstopPercentage",
        "type": "uint256",
        "internalType": "UD60x18"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "AccountAboveAdl",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountAboveIMBuffer",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountAboveLm",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidBackstopPercentage",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "backstopPercentage",
        "type": "uint256",
        "internalType": "UD60x18"
      }
    ]
  },
  {
    "type": "function",
    "name": "executeLiquidationBid",
    "inputs": [
      {
        "name": "liquidatableAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "bidSubmissionKeeperId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "liquidationBid",
        "type": "tuple",
        "internalType": "struct LiquidationBid",
        "components": [
          {
            "name": "liquidatorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "hookAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "liquidatorRewardParameter",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteCollateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marketIds",
            "type": "uint128[]",
            "internalType": "uint128[]"
          },
          {
            "name": "inputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "output",
        "type": "tuple",
        "internalType": "struct ExecuteLiquidationBidOutput",
        "components": [
          {
            "name": "lmrDelta",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "rewards",
            "type": "tuple",
            "internalType": "struct LiquidationRewards",
            "components": [
              {
                "name": "insuranceFund",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "backstopLP",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "keeper",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "liquidator",
                "type": "uint256",
                "internalType": "uint256"
              }
            ]
          },
          {
            "name": "marketOutputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "AccountInsolvent",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "marginBalance",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "CheckSelfCall",
    "inputs": [
      {
        "name": "caller",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "IncreasedLmDueLiquidation",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "lmrBefore",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "lmrAfter",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidPostLiquidationHookResponse",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidPreLiquidationHookResponse",
    "inputs": []
  },
  {
    "type": "function",
    "name": "executeDutchLiquidation",
    "inputs": [
      {
        "name": "liquidatorAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "data",
        "type": "tuple",
        "internalType": "struct DutchLiquidationInput",
        "components": [
          {
            "name": "liquidatableAccountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "quoteCollateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marketIds",
            "type": "uint128[]",
            "internalType": "uint128[]"
          },
          {
            "name": "inputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct DutchLiquidationOutput",
        "components": [
          {
            "name": "lmrDelta",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "healthPre",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "rewardParameter",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "rewards",
            "type": "tuple",
            "internalType": "struct LiquidationRewards",
            "components": [
              {
                "name": "insuranceFund",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "backstopLP",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "keeper",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "liquidator",
                "type": "uint256",
                "internalType": "uint256"
              }
            ]
          },
          {
            "name": "marketOutputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "AccountAboveDutch",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountBelowAdl",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "InvalidMarketIdOrder",
    "inputs": [
      {
        "name": "marketIds",
        "type": "uint128[]",
        "internalType": "uint128[]"
      }
    ]
  },
  {
    "type": "error",
    "name": "LiquidationBidOrdersOverflow",
    "inputs": [
      {
        "name": "numberOfOrders",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "maxOrders",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "MarketsAndInputsMismatch",
    "inputs": [
      {
        "name": "numberOfMarketIds",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "numberOfInputs",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "NonActiveMarketInLiquidationBid",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ]
  },
  {
    "type": "error",
    "name": "ZeroLiquidationBidOrders",
    "inputs": []
  },
  {
    "type": "function",
    "name": "executeTopRankedLiquidationBid",
    "inputs": [
      {
        "name": "liquidatableAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "bidSubmissionKeeperId",
        "type": "uint128",
        "internalType": "uint128"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct ExecuteTopRankedLiquidationBidOutput",
        "components": [
          {
            "name": "success",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "bidQueueIndex",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidIndex",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "executionOutput",
            "type": "tuple",
            "internalType": "struct ExecuteLiquidationBidOutput",
            "components": [
              {
                "name": "lmrDelta",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "rewards",
                "type": "tuple",
                "internalType": "struct LiquidationRewards",
                "components": [
                  {
                    "name": "insuranceFund",
                    "type": "uint256",
                    "internalType": "uint256"
                  },
                  {
                    "name": "backstopLP",
                    "type": "uint256",
                    "internalType": "uint256"
                  },
                  {
                    "name": "keeper",
                    "type": "uint256",
                    "internalType": "uint256"
                  },
                  {
                    "name": "liquidator",
                    "type": "uint256",
                    "internalType": "uint256"
                  }
                ]
              },
              {
                "name": "marketOutputs",
                "type": "bytes[]",
                "internalType": "bytes[]"
              }
            ]
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "EmptyLiquidationBidQueue",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "error",
    "name": "IncorrectLiquidationHookInterface",
    "inputs": [
      {
        "name": "liquidationBid",
        "type": "tuple",
        "internalType": "struct LiquidationBid",
        "components": [
          {
            "name": "liquidatorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "hookAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "liquidatorRewardParameter",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteCollateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marketIds",
            "type": "uint128[]",
            "internalType": "uint128[]"
          },
          {
            "name": "inputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ]
  },
  {
    "type": "error",
    "name": "LiquidationBidRewardOverflow",
    "inputs": [
      {
        "name": "liquidationBid",
        "type": "tuple",
        "internalType": "struct LiquidationBid",
        "components": [
          {
            "name": "liquidatorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "hookAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "liquidatorRewardParameter",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteCollateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marketIds",
            "type": "uint128[]",
            "internalType": "uint128[]"
          },
          {
            "name": "inputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ]
  },
  {
    "type": "function",
    "name": "getLiquidationBidQueue",
    "inputs": [
      {
        "name": "liquidatableAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "quoteCollateral",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "output",
        "type": "tuple",
        "internalType": "struct LiquidationBidQueueOutput",
        "components": [
          {
            "name": "bidQueueIndex",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expirationTimestamp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bids",
            "type": "tuple[]",
            "internalType": "struct LiquidationBidQueueItem[]",
            "components": [
              {
                "name": "index",
                "type": "uint256",
                "internalType": "uint256"
              },
              {
                "name": "bid",
                "type": "tuple",
                "internalType": "struct LiquidationBid",
                "components": [
                  {
                    "name": "liquidatorAccountId",
                    "type": "uint128",
                    "internalType": "uint128"
                  },
                  {
                    "name": "hookAddress",
                    "type": "address",
                    "internalType": "address"
                  },
                  {
                    "name": "liquidatorRewardParameter",
                    "type": "uint256",
                    "internalType": "UD60x18"
                  },
                  {
                    "name": "quoteCollateral",
                    "type": "address",
                    "internalType": "address"
                  },
                  {
                    "name": "marketIds",
                    "type": "uint128[]",
                    "internalType": "uint128[]"
                  },
                  {
                    "name": "inputs",
                    "type": "bytes[]",
                    "internalType": "bytes[]"
                  }
                ]
              },
              {
                "name": "score",
                "type": "uint256",
                "internalType": "uint256"
              }
            ]
          }
        ]
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "submitLiquidationBid",
    "inputs": [
      {
        "name": "liquidatableAccountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "liquidationBid",
        "type": "tuple",
        "internalType": "struct LiquidationBid",
        "components": [
          {
            "name": "liquidatorAccountId",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "hookAddress",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "liquidatorRewardParameter",
            "type": "uint256",
            "internalType": "UD60x18"
          },
          {
            "name": "quoteCollateral",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "marketIds",
            "type": "uint128[]",
            "internalType": "uint128[]"
          },
          {
            "name": "inputs",
            "type": "bytes[]",
            "internalType": "bytes[]"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "tuple",
        "internalType": "struct SubmitLiquidationBidOutput",
        "components": [
          {
            "name": "bidQueueIndex",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidScore",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "bidIndex",
            "type": "uint256",
            "internalType": "uint256"
          }
        ]
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "AccountAboveMmr",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AccountBelowLm",
    "inputs": [
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "delta",
        "type": "int256",
        "internalType": "int256"
      }
    ]
  },
  {
    "type": "error",
    "name": "LiquidationBidQueueOverflow",
    "inputs": []
  },
  {
    "type": "error",
    "name": "PRBMath_UD60x18_Convert_Overflow",
    "inputs": [
      {
        "name": "x",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "name": "executeMatchOrder",
    "inputs": [
      {
        "name": "caller",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "marketId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "accountId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "exchangeId",
        "type": "uint128",
        "internalType": "uint128"
      },
      {
        "name": "counterpartyAccountIds",
        "type": "uint128[]",
        "internalType": "uint128[]"
      },
      {
        "name": "orderInputs",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "output",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "error",
    "name": "InvalidMatchOrderFees",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NoCounterpartiesInMatchOrder",
    "inputs": []
  }
]"
);

#[tokio::main]
async fn main() -> eyre::Result<()> {
    println!("Hello, world!");
    
    eyre::Ok(())
}
