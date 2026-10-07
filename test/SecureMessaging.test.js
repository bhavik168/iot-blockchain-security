const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture, time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { addressToIdentifier } = require("../lib/merkle");
const { Verdict, signDeviceMessage, messagingDomain, MESSAGE_TYPES } = require("../lib/eip712");

const ONE_DAY = 24 * 60 * 60;

describe("SecureMessaging", function () {
  async function deployFixture() {
    const [owner, otherOwner, relayer] = await ethers.getSigners();
    const manager = await ethers.deployContract("DeviceManager");
    const messaging = await ethers.deployContract("SecureMessaging", [await manager.getAddress()]);

    // Device 0: sensor (owner), device 1: actuator (owner), device 2: rogue device (otherOwner)
    const sensorKey = ethers.Wallet.createRandom();
    const actuatorKey = ethers.Wallet.createRandom();
    const rogueKey = ethers.Wallet.createRandom();
    await manager.connect(owner).createDevice(addressToIdentifier(sensorKey.address), ethers.ZeroHash, ethers.ZeroHash);
    await manager.connect(owner).createDevice(addressToIdentifier(actuatorKey.address), ethers.ZeroHash, ethers.ZeroHash);
    await manager.connect(otherOwner).createDevice(addressToIdentifier(rogueKey.address), ethers.ZeroHash, ethers.ZeroHash);

    const accessExpiry = (await time.latest()) + ONE_DAY;
    await messaging.connect(owner).grantAccess(1, 0, accessExpiry);

    return { manager, messaging, owner, otherOwner, relayer, sensorKey, actuatorKey, rogueKey, accessExpiry };
  }

  async function buildMessage(messaging, wallet, overrides = {}) {
    const message = {
      senderId: 0n,
      receiverId: 1n,
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes('{"temp":21.5}')),
      nonce: await messaging.nonces(overrides.senderId ?? 0n),
      deadline: BigInt((await time.latest()) + 300),
      ...overrides,
    };
    return signDeviceMessage(messaging, wallet, message);
  }

  function args({ message, signature }) {
    return [message.senderId, message.receiverId, message.payloadHash, message.nonce, message.deadline, signature];
  }

  describe("access control", function () {
    it("lets the receiver owner grant and revoke access", async function () {
      const { messaging, owner, accessExpiry } = await loadFixture(deployFixture);
      expect(await messaging.accessExpiry(1, 0)).to.equal(BigInt(accessExpiry));
      expect(await messaging.canSend(0, 1)).to.equal(true);
      expect(await messaging.canSend(1, 0)).to.equal(false);

      await expect(messaging.connect(owner).revokeAccess(1, 0)).to.emit(messaging, "AccessRevoked").withArgs(1n, 0n);
      expect(await messaging.canSend(0, 1)).to.equal(false);
    });

    it("rejects grants from non-owners, to self and with past expiry", async function () {
      const { messaging, manager, owner, otherOwner } = await loadFixture(deployFixture);
      const expiry = (await time.latest()) + ONE_DAY;
      await expect(messaging.connect(otherOwner).grantAccess(1, 2, expiry))
        .to.be.revertedWithCustomError(messaging, "NotDeviceOwner")
        .withArgs(1n, otherOwner.address);
      await expect(messaging.connect(otherOwner).revokeAccess(1, 0))
        .to.be.revertedWithCustomError(messaging, "NotDeviceOwner");
      await expect(messaging.connect(owner).grantAccess(1, 1, expiry))
        .to.be.revertedWithCustomError(messaging, "SelfAccess");
      await expect(messaging.connect(owner).grantAccess(1, 0, await time.latest()))
        .to.be.revertedWithCustomError(messaging, "InvalidAccessExpiry");
      await expect(messaging.connect(owner).grantAccess(99, 0, expiry))
        .to.be.revertedWithCustomError(manager, "DeviceNotFound");
    });

    it("expires access automatically", async function () {
      const { messaging } = await loadFixture(deployFixture);
      await time.increase(ONE_DAY + 1);
      expect(await messaging.canSend(0, 1)).to.equal(false);
    });
  });

  describe("encryption keys", function () {
    it("can be published by the owner or by the device itself", async function () {
      const { messaging, owner, sensorKey } = await loadFixture(deployFixture);
      const key1 = ethers.hexlify(ethers.randomBytes(32));
      await expect(messaging.connect(owner).publishEncryptionKey(0, key1))
        .to.emit(messaging, "EncryptionKeyPublished")
        .withArgs(0n, key1);

      const deviceSigner = sensorKey.connect(ethers.provider);
      await owner.sendTransaction({ to: sensorKey.address, value: ethers.parseEther("1") });
      const key2 = ethers.hexlify(ethers.randomBytes(32));
      await messaging.connect(deviceSigner).publishEncryptionKey(0, key2);
      expect(await messaging.encryptionKeyOf(0)).to.equal(key2);
    });

    it("rejects strangers, empty keys and inactive devices", async function () {
      const { messaging, manager, owner, otherOwner } = await loadFixture(deployFixture);
      const key = ethers.hexlify(ethers.randomBytes(32));
      await expect(messaging.connect(otherOwner).publishEncryptionKey(0, key))
        .to.be.revertedWithCustomError(messaging, "NotDeviceController");
      await expect(messaging.connect(owner).publishEncryptionKey(0, ethers.ZeroHash))
        .to.be.revertedWithCustomError(messaging, "InvalidPublicKey");
      await manager.connect(owner).suspendDevice(0);
      await expect(messaging.connect(owner).publishEncryptionKey(0, key))
        .to.be.revertedWithCustomError(messaging, "DeviceNotActive");
    });
  });

  describe("message verification", function () {
    it("matches the EIP-712 digest computed off-chain", async function () {
      const { messaging, sensorKey } = await loadFixture(deployFixture);
      const { message } = await buildMessage(messaging, sensorKey);
      const offChain = ethers.TypedDataEncoder.hash(await messagingDomain(messaging), MESSAGE_TYPES, message);
      expect(
        await messaging.hashMessage(message.senderId, message.receiverId, message.payloadHash, message.nonce, message.deadline)
      ).to.equal(offChain);
    });

    it("accepts a valid signed message", async function () {
      const { messaging, sensorKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, sensorKey);
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.Valid);
    });

    it("rejects a tampered payload", async function () {
      const { messaging, sensorKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, sensorKey);
      signed.message.payloadHash = ethers.keccak256(ethers.toUtf8Bytes('{"temp":99}'));
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.InvalidSignature);
    });

    it("rejects a message signed by the wrong key (impersonation)", async function () {
      const { messaging, rogueKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, rogueKey);
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.InvalidSignature);
      expect(await messaging.verifyMessage(...args({ ...signed, signature: "0xdead" }))).to.equal(
        Verdict.InvalidSignature
      );
    });

    it("rejects unauthorised senders", async function () {
      const { messaging, rogueKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, rogueKey, { senderId: 2n });
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.NotAuthorized);
    });

    it("rejects expired messages", async function () {
      const { messaging, sensorKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, sensorKey);
      await time.increase(301);
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.Expired);
    });

    it("rejects messages from or to inactive devices", async function () {
      const { messaging, manager, owner, sensorKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, sensorKey);
      await manager.connect(owner).suspendDevice(1);
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.ReceiverInactive);
      await manager.connect(owner).revokeDevice(0);
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.SenderInactive);
    });
  });

  describe("anchoring", function () {
    it("anchors a valid message relayed by anyone and consumes the nonce", async function () {
      const { messaging, relayer, sensorKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, sensorKey);
      const digest = await messaging.hashMessage(...args(signed).slice(0, 5));

      await expect(messaging.connect(relayer).anchorMessage(...args(signed)))
        .to.emit(messaging, "MessageAnchored")
        .withArgs(digest, 0n, 1n, signed.message.payloadHash, 0n);
      expect(await messaging.nonces(0)).to.equal(1n);
      expect(await messaging.anchoredAt(digest)).to.equal(BigInt(await time.latest()));
    });

    it("blocks replay of an anchored message", async function () {
      const { messaging, relayer, sensorKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, sensorKey);
      await messaging.connect(relayer).anchorMessage(...args(signed));
      await expect(messaging.connect(relayer).anchorMessage(...args(signed)))
        .to.be.revertedWithCustomError(messaging, "MessageRejected")
        .withArgs(Verdict.InvalidNonce);

      const next = await buildMessage(messaging, sensorKey);
      expect(next.message.nonce).to.equal(1n);
      await messaging.connect(relayer).anchorMessage(...args(next));
    });

    it("reverts with the verdict for invalid messages", async function () {
      const { messaging, relayer, rogueKey } = await loadFixture(deployFixture);
      const signed = await buildMessage(messaging, rogueKey);
      await expect(messaging.connect(relayer).anchorMessage(...args(signed)))
        .to.be.revertedWithCustomError(messaging, "MessageRejected")
        .withArgs(Verdict.InvalidSignature);
    });

    it("signatures are bound to this deployment (cross-contract replay)", async function () {
      const { messaging, manager, owner, sensorKey } = await loadFixture(deployFixture);
      const other = await ethers.deployContract("SecureMessaging", [await manager.getAddress()]);
      await other.connect(owner).grantAccess(1, 0, (await time.latest()) + ONE_DAY);
      const signed = await buildMessage(messaging, sensorKey);
      expect(await messaging.verifyMessage(...args(signed))).to.equal(Verdict.Valid);
      expect(await other.verifyMessage(...args(signed))).to.equal(Verdict.InvalidSignature);
    });
  });
});
