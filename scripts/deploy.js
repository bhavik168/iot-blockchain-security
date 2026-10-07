const fs = require("node:fs");
const path = require("node:path");
const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying to "${network.name}" from ${deployer.address}`);

  const manager = await ethers.deployContract("DeviceManager");
  await manager.waitForDeployment();
  console.log(`DeviceManager   -> ${await manager.getAddress()}`);

  const messaging = await ethers.deployContract("SecureMessaging", [await manager.getAddress()]);
  await messaging.waitForDeployment();
  console.log(`SecureMessaging -> ${await messaging.getAddress()}`);

  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `${network.name}.json`);
  fs.writeFileSync(
    outFile,
    JSON.stringify(
      {
        network: network.name,
        chainId: Number((await ethers.provider.getNetwork()).chainId),
        deployer: deployer.address,
        DeviceManager: await manager.getAddress(),
        SecureMessaging: await messaging.getAddress(),
        deployedAt: new Date().toISOString(),
      },
      null,
      2
    )
  );
  console.log(`Saved addresses to ${path.relative(process.cwd(), outFile)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
