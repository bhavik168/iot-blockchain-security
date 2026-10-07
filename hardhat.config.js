require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "cancun",
    },
  },
  networks: {
    hardhat: {},
    localhost: { url: "http://127.0.0.1:8545" },
    // Optional public testnet. Set SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY to use it.
    ...(process.env.SEPOLIA_RPC_URL && process.env.DEPLOYER_PRIVATE_KEY
      ? {
          sepolia: {
            url: process.env.SEPOLIA_RPC_URL,
            accounts: [process.env.DEPLOYER_PRIVATE_KEY],
          },
        }
      : {}),
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },
};
