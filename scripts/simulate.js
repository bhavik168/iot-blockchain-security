/**
 * End-to-end simulation of secure IoT communication.
 *
 *   npx hardhat run scripts/simulate.js
 *
 * Actors: a manufacturer (attests devices), a home owner, a gateway (relays messages, pays gas),
 * a temperature sensor and a smart thermostat valve. The script walks through onboarding, encrypted
 * messaging, and five attacks that the system must reject.
 */
const { ethers } = require("hardhat");
const { MetadataTree, firmwareCommitment, addressToIdentifier } = require("../lib/merkle");
const { signDeviceMessage, VERDICT_NAMES } = require("../lib/eip712");
const { generateEncryptionKeyPair, encryptPayload, decryptPayload } = require("../lib/crypto");

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};
const step = (title) => console.log(`\n${c.bold(`== ${title} ==`)}`);
const ok = (msg) => console.log(`  ${c.green("✔")} ${msg}`);
const blocked = (msg) => console.log(`  ${c.red("✘")} ${msg}`);
const info = (msg) => console.log(`  ${c.dim(msg)}`);

/** Represents a physical device: its signing key (secp256k1) and encryption key (X25519). */
class SimulatedDevice {
  constructor(name, metadata, firmware) {
    this.name = name;
    this.wallet = ethers.Wallet.createRandom();
    this.encryption = generateEncryptionKeyPair();
    this.metadata = new MetadataTree(metadata);
    this.firmware = firmwareCommitment(ethers.toUtf8Bytes(firmware));
    this.id = undefined;
  }
}

async function main() {
  const [manufacturer, homeOwner, gateway, attacker] = await ethers.getSigners();

  step("1. Deploy contracts");
  const manager = await ethers.deployContract("DeviceManager");
  const messaging = await ethers.deployContract("SecureMessaging", [await manager.getAddress()]);
  ok(`DeviceManager   ${await manager.getAddress()}`);
  ok(`SecureMessaging ${await messaging.getAddress()}`);

  step("2. Register entities and devices");
  await manager.connect(manufacturer).updateEntityData("Acme IoT Ltd. | https://acme.example");
  ok(`Manufacturer profile: "${await manager.ownerToEntity(manufacturer.address)}"`);

  const sensor = new SimulatedDevice(
    "Temperature sensor",
    { manufacturer: "Acme IoT", model: "TS-100", serial: "TS-2024-0001", location: "living-room" },
    "ts-100 firmware v2.3.1"
  );
  const valve = new SimulatedDevice(
    "Thermostat valve",
    { manufacturer: "Acme IoT", model: "TV-300", serial: "TV-2024-0042", location: "living-room" },
    "tv-300 firmware v1.8.0"
  );
  for (const device of [sensor, valve]) {
    const tx = await manager
      .connect(homeOwner)
      .createDevice(addressToIdentifier(device.wallet.address), device.metadata.root, device.firmware);
    const receipt = await tx.wait();
    device.id = manager.interface.parseLog(receipt.logs[0]).args.deviceId;
    ok(`${device.name} registered as device #${device.id} (key ${device.wallet.address})`);
  }

  step("3. Manufacturer attests both devices");
  const latest = (await ethers.provider.getBlock("latest")).timestamp;
  for (const device of [sensor, valve]) {
    await manager.connect(manufacturer).attestDevice(device.id, latest + 365 * 24 * 3600);
    ok(`${device.name} trusted: ${await manager.isTrusted(device.id)}`);
  }

  step("4. Selective disclosure: prove the sensor model without revealing its serial");
  const proof = sensor.metadata.proof("model");
  const proven = await manager.isValidMetadataMember(sensor.id, proof, sensor.metadata.leaf("model"));
  ok(`"model:TS-100" is part of device #${sensor.id} metadata: ${proven} (proof of ${proof.length} hashes)`);

  step("5. Key exchange and access control");
  for (const device of [sensor, valve]) {
    await messaging.connect(homeOwner).publishEncryptionKey(device.id, device.encryption.publicKey);
    ok(`${device.name} published X25519 key ${device.encryption.publicKey.slice(0, 18)}...`);
  }
  await messaging.connect(homeOwner).grantAccess(valve.id, sensor.id, latest + 30 * 24 * 3600);
  ok(`Owner allowed sensor #${sensor.id} -> valve #${valve.id} for 30 days`);

  /** Sensor encrypts + signs a reading; gateway verifies and anchors; valve decrypts. */
  async function sendReading(from, to, plaintext, { signer = from.wallet } = {}) {
    const peerKey = await messaging.encryptionKeyOf(to.id);
    const envelope = encryptPayload({
      privateKey: from.encryption.privateKey,
      peerPublicKey: peerKey,
      senderId: from.id,
      receiverId: to.id,
      plaintext,
    });
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const signed = await signDeviceMessage(messaging, signer, {
      senderId: from.id,
      receiverId: to.id,
      payloadHash: ethers.keccak256(envelope),
      nonce: await messaging.nonces(from.id),
      deadline: BigInt(now + 60),
    });
    return { envelope, ...signed };
  }

  async function gatewayRelay(packet) {
    const { message: m, signature } = packet;
    const args = [m.senderId, m.receiverId, m.payloadHash, m.nonce, m.deadline, signature];
    const verdict = await messaging.verifyMessage(...args);
    if (verdict !== 0n) return VERDICT_NAMES[verdict.toString()];
    await (await messaging.connect(gateway).anchorMessage(...args)).wait();
    return "Valid";
  }

  step("6. Secure message: sensor -> valve");
  const reading = JSON.stringify({ temperature: 17.2, unit: "C", ts: Date.now() });
  const packet = await sendReading(sensor, valve, reading);
  info(`ciphertext ${packet.envelope.slice(0, 42)}... (${(packet.envelope.length - 2) / 2} bytes)`);
  ok(`Gateway verdict: ${await gatewayRelay(packet)} — message anchored, nonce now ${await messaging.nonces(sensor.id)}`);

  // Receiver side: check the envelope matches what was anchored, then decrypt.
  const digest = await messaging.hashMessage(
    packet.message.senderId,
    packet.message.receiverId,
    ethers.keccak256(packet.envelope),
    packet.message.nonce,
    packet.message.deadline
  );
  ok(`Valve found anchor receipt at block time ${await messaging.anchoredAt(digest)}`);
  const decrypted = decryptPayload({
    privateKey: valve.encryption.privateKey,
    peerPublicKey: await messaging.encryptionKeyOf(sensor.id),
    senderId: sensor.id,
    receiverId: valve.id,
    envelope: packet.envelope,
  });
  ok(`Valve decrypted: ${decrypted}`);

  step("7. Attacks");
  // a) Replay
  const replay = await gatewayRelay(packet);
  (replay === "Valid" ? ok : blocked)(`Replay of the same packet -> ${replay}`);

  // b) Tampering in transit
  const tampered = await sendReading(sensor, valve, JSON.stringify({ temperature: 35.0 }));
  tampered.message.payloadHash = ethers.keccak256(ethers.toUtf8Bytes("forged"));
  blocked(`Payload modified in transit -> ${await gatewayRelay(tampered)}`);

  // c) Impersonation: attacker signs pretending to be the sensor
  const fake = await sendReading(sensor, valve, JSON.stringify({ temperature: 5 }), {
    signer: ethers.Wallet.createRandom(),
  });
  blocked(`Attacker-signed message claiming to be the sensor -> ${await gatewayRelay(fake)}`);

  // d) Unauthorised device: attacker registers their own device and tries to talk to the valve
  const rogue = new SimulatedDevice("Rogue device", { model: "EVIL-1" }, "malware");
  await manager.connect(attacker).createDevice(addressToIdentifier(rogue.wallet.address), rogue.metadata.root, rogue.firmware);
  rogue.id = (await manager.totalDevices()) - 1n;
  await messaging.connect(attacker).publishEncryptionKey(rogue.id, rogue.encryption.publicKey);
  blocked(`Unauthorised rogue device #${rogue.id} -> ${await gatewayRelay(await sendReading(rogue, valve, "open"))}`);
  try {
    await messaging.connect(attacker).grantAccess(valve.id, rogue.id, latest + 3600);
  } catch (e) {
    blocked(`Attacker granting itself access -> ${messaging.interface.parseError(e.data)?.name ?? e.shortMessage}`);
  }

  // e) Firmware tampering detected, device revoked after compromise
  const backdoored = firmwareCommitment(ethers.toUtf8Bytes("ts-100 firmware v2.3.1 + backdoor"));
  blocked(`Firmware report with backdoor matches registry: ${await manager.isValidFirmwareHash(sensor.id, backdoored)}`);
  await manager.connect(homeOwner).revokeDevice(sensor.id);
  blocked(`Sensor revoked by owner, next message -> ${await gatewayRelay(await sendReading(sensor, valve, "{}"))}`);

  step("Summary");
  ok(`Messages anchored: ${await messaging.nonces(sensor.id)}`);
  ok(`Sensor trusted: ${await manager.isTrusted(sensor.id)}, valve trusted: ${await manager.isTrusted(valve.id)}`);
  console.log();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
