const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture, time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { MetadataTree, firmwareCommitment, addressToIdentifier } = require("../lib/merkle");

const Status = { None: 0n, Active: 1n, Suspended: 2n, Revoked: 3n };
const ONE_DAY = 24 * 60 * 60;

describe("DeviceManager", function () {
  async function deployFixture() {
    const [owner, manufacturer, auditor, buyer, stranger] = await ethers.getSigners();
    const manager = await ethers.deployContract("DeviceManager");

    const deviceKey = ethers.Wallet.createRandom();
    const metadata = new MetadataTree({
      manufacturer: "Acme IoT",
      model: "TH-200",
      serial: "SN-0001",
      hwRevision: "B",
    });
    const firmware = firmwareCommitment(ethers.toUtf8Bytes("firmware v1.0.0"));
    const identifier = addressToIdentifier(deviceKey.address);

    await manager.connect(owner).createDevice(identifier, metadata.root, firmware);

    return { manager, owner, manufacturer, auditor, buyer, stranger, deviceKey, metadata, firmware, identifier };
  }

  async function future(seconds = ONE_DAY) {
    return (await time.latest()) + seconds;
  }

  describe("entities", function () {
    it("stores and emits entity data", async function () {
      const { manager, manufacturer } = await loadFixture(deployFixture);
      await expect(manager.connect(manufacturer).updateEntityData("Acme IoT Ltd."))
        .to.emit(manager, "EntityDataUpdated")
        .withArgs(manufacturer.address, "Acme IoT Ltd.");
      expect(await manager.ownerToEntity(manufacturer.address)).to.equal("Acme IoT Ltd.");
    });
  });

  describe("device registration", function () {
    it("creates a device with correct properties", async function () {
      const { manager, owner, deviceKey, metadata, firmware, identifier } = await loadFixture(deployFixture);
      const device = await manager.getDevice(0);
      expect(device.owner).to.equal(owner.address);
      expect(device.status).to.equal(Status.Active);
      expect(device.identifier).to.equal(identifier);
      expect(device.metadataHash).to.equal(metadata.root);
      expect(device.firmwareHash).to.equal(firmware);
      expect(await manager.signerOf(0)).to.equal(deviceKey.address);
      expect(await manager.deviceIdOf(identifier)).to.equal(0n);
      expect(await manager.totalDevices()).to.equal(1n);
    });

    it("emits DeviceCreated", async function () {
      const { manager, owner } = await loadFixture(deployFixture);
      const id = addressToIdentifier(ethers.Wallet.createRandom().address);
      await expect(manager.createDevice(id, ethers.ZeroHash, ethers.ZeroHash))
        .to.emit(manager, "DeviceCreated")
        .withArgs(1n, owner.address, id, ethers.ZeroHash, ethers.ZeroHash);
    });

    it("rejects empty and duplicate identifiers", async function () {
      const { manager, stranger, identifier } = await loadFixture(deployFixture);
      await expect(manager.createDevice(ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash))
        .to.be.revertedWithCustomError(manager, "InvalidIdentifier");
      await expect(manager.connect(stranger).createDevice(identifier, ethers.ZeroHash, ethers.ZeroHash))
        .to.be.revertedWithCustomError(manager, "IdentifierAlreadyRegistered")
        .withArgs(identifier, 0n);
    });

    it("lists devices per owner", async function () {
      const { manager, owner, stranger } = await loadFixture(deployFixture);
      await manager.connect(stranger).createDevice(addressToIdentifier(stranger.address), ethers.ZeroHash, ethers.ZeroHash);
      await manager.createDevice(addressToIdentifier(ethers.Wallet.createRandom().address), ethers.ZeroHash, ethers.ZeroHash);
      expect(await manager.getDevicesByOwner(owner.address)).to.deep.equal([0n, 2n]);
      expect(await manager.getDevicesByOwner(stranger.address)).to.deep.equal([1n]);
      expect(await manager.ownerDeviceCount(owner.address)).to.equal(2n);
    });

    it("reverts with DeviceNotFound for unknown IDs", async function () {
      const { manager } = await loadFixture(deployFixture);
      await expect(manager.getDevice(42)).to.be.revertedWithCustomError(manager, "DeviceNotFound").withArgs(42n);
      await expect(manager.isDeviceAnEntity(42)).to.be.revertedWithCustomError(manager, "DeviceNotFound");
      expect(await manager.isActive(42)).to.equal(false);
    });

    it("detects devices that are their own entity", async function () {
      const { manager, owner, stranger } = await loadFixture(deployFixture);
      expect(await manager.isDeviceAnEntity(0)).to.equal(false);
      await manager.connect(stranger).createDevice(addressToIdentifier(stranger.address), ethers.ZeroHash, ethers.ZeroHash);
      expect(await manager.isDeviceAnEntity(1)).to.equal(true);
      expect(owner.address).to.not.equal(stranger.address);
    });
  });

  describe("integrity and authenticity checks", function () {
    it("verifies metadata membership with a Merkle proof", async function () {
      const { manager, metadata } = await loadFixture(deployFixture);
      for (const key of ["manufacturer", "model", "serial", "hwRevision"]) {
        expect(await manager.isValidMetadataMember(0, metadata.proof(key), metadata.leaf(key))).to.equal(true);
      }
      const forged = new MetadataTree({ model: "TH-999" });
      expect(await manager.isValidMetadataMember(0, metadata.proof("model"), forged.leaf("model"))).to.equal(false);
    });

    it("verifies firmware commitments", async function () {
      const { manager, firmware } = await loadFixture(deployFixture);
      expect(await manager.isValidFirmwareHash(0, firmware)).to.equal(true);
      const tampered = firmwareCommitment(ethers.toUtf8Bytes("firmware v1.0.0 + backdoor"));
      expect(await manager.isValidFirmwareHash(0, tampered)).to.equal(false);
    });

    it("verifies messages signed by the device key (EIP-191)", async function () {
      const { manager, deviceKey } = await loadFixture(deployFixture);
      const messageHash = ethers.keccak256(ethers.toUtf8Bytes("temperature=21.5"));
      const signature = await deviceKey.signMessage(ethers.getBytes(messageHash));
      expect(await manager.isValidEthMessage(0, messageHash, signature)).to.equal(true);

      const otherKey = ethers.Wallet.createRandom();
      const forged = await otherKey.signMessage(ethers.getBytes(messageHash));
      expect(await manager.isValidEthMessage(0, messageHash, forged)).to.equal(false);
      expect(await manager.isValidEthMessage(0, messageHash, "0x1234")).to.equal(false);
    });
  });

  describe("attestations", function () {
    it("lets a third party attest a device", async function () {
      const { manager, manufacturer } = await loadFixture(deployFixture);
      const expiry = await future();
      await expect(manager.connect(manufacturer).attestDevice(0, expiry))
        .to.emit(manager, "DeviceAttested")
        .withArgs(0n, 0n, manufacturer.address, expiry);
      expect(await manager.isAttestationValid(0)).to.equal(true);
      expect(await manager.isAttestedBy(0, manufacturer.address)).to.equal(true);
      expect(await manager.isTrusted(0)).to.equal(true);
      expect(await manager.getActiveAttestationsForDevice(0)).to.deep.equal([0n]);
    });

    it("exposes attestation details", async function () {
      const { manager, manufacturer } = await loadFixture(deployFixture);
      const expiry = await future();
      await manager.connect(manufacturer).attestDevice(0, expiry);
      const attestation = await manager.getAttestation(0);
      expect(attestation.attester).to.equal(manufacturer.address);
      expect(attestation.expiryTime).to.equal(BigInt(expiry));
      expect(attestation.revoked).to.equal(false);
      expect(await manager.totalAttestations()).to.equal(1n);
      expect(await manager.isAttestationValid(5)).to.equal(false);
      await expect(manager.getAttestation(5)).to.be.revertedWithCustomError(manager, "AttestationNotFound");
      await expect(manager.deviceIdOf(ethers.ZeroHash)).to.be.revertedWithCustomError(manager, "InvalidIdentifier");
    });

    it("rejects self-attestation, past expiry, duplicates and unknown devices", async function () {
      const { manager, owner, manufacturer } = await loadFixture(deployFixture);
      await expect(manager.connect(owner).attestDevice(0, await future()))
        .to.be.revertedWithCustomError(manager, "SelfAttestation");
      await expect(manager.connect(manufacturer).attestDevice(0, await time.latest()))
        .to.be.revertedWithCustomError(manager, "InvalidExpiryTime");
      await expect(manager.connect(manufacturer).attestDevice(7, await future()))
        .to.be.revertedWithCustomError(manager, "DeviceNotActive");

      await manager.connect(manufacturer).attestDevice(0, await future());
      await expect(manager.connect(manufacturer).attestDevice(0, await future()))
        .to.be.revertedWithCustomError(manager, "AlreadyAttested");
    });

    it("expires attestations and allows re-attestation", async function () {
      const { manager, manufacturer } = await loadFixture(deployFixture);
      await manager.connect(manufacturer).attestDevice(0, await future(60));
      await time.increase(61);
      expect(await manager.isAttestationValid(0)).to.equal(false);
      expect(await manager.isTrusted(0)).to.equal(false);
      await manager.connect(manufacturer).attestDevice(0, await future());
      expect(await manager.getActiveAttestationsForDevice(0)).to.deep.equal([1n]);
      expect(await manager.getAttestationsForDevice(0)).to.deep.equal([0n, 1n]);
    });

    it("only the attester can revoke, and only once", async function () {
      const { manager, manufacturer, stranger } = await loadFixture(deployFixture);
      await manager.connect(manufacturer).attestDevice(0, await future());
      await expect(manager.connect(stranger).revokeAttestation(0))
        .to.be.revertedWithCustomError(manager, "NotAttester");
      await expect(manager.connect(manufacturer).revokeAttestation(0))
        .to.emit(manager, "AttestationRevoked")
        .withArgs(0n, 0n);
      await expect(manager.connect(manufacturer).revokeAttestation(0))
        .to.be.revertedWithCustomError(manager, "AttestationAlreadyRevoked");
      await expect(manager.revokeAttestation(9)).to.be.revertedWithCustomError(manager, "AttestationNotFound");
      expect(await manager.isAttestationValid(0)).to.equal(false);
    });

    it("invalidates attestations when firmware changes", async function () {
      const { manager, owner, manufacturer, auditor } = await loadFixture(deployFixture);
      await manager.connect(manufacturer).attestDevice(0, await future());
      await manager.connect(auditor).attestDevice(0, await future());
      expect(await manager.getActiveAttestationsForDevice(0)).to.have.length(2);

      const newFirmware = firmwareCommitment(ethers.toUtf8Bytes("firmware v1.1.0"));
      await manager.connect(owner).updateFirmwareHash(0, newFirmware);

      expect(await manager.getActiveAttestationsForDevice(0)).to.have.length(0);
      expect(await manager.isTrusted(0)).to.equal(false);

      // Manufacturer re-attests the new firmware.
      await manager.connect(manufacturer).attestDevice(0, await future());
      expect(await manager.isTrusted(0)).to.equal(true);
    });
  });

  describe("lifecycle", function () {
    it("transfers ownership and keeps attestations", async function () {
      const { manager, owner, manufacturer, buyer } = await loadFixture(deployFixture);
      await manager.connect(manufacturer).attestDevice(0, await future());
      await expect(manager.connect(owner).transferDevice(0, buyer.address))
        .to.emit(manager, "DeviceTransferred")
        .withArgs(0n, owner.address, buyer.address);
      expect(await manager.ownerOf(0)).to.equal(buyer.address);
      expect(await manager.getDevicesByOwner(owner.address)).to.deep.equal([]);
      expect(await manager.getDevicesByOwner(buyer.address)).to.deep.equal([0n]);
      expect(await manager.isTrusted(0)).to.equal(true);
    });

    it("guards owner-only functions and recipients", async function () {
      const { manager, owner, stranger } = await loadFixture(deployFixture);
      await expect(manager.connect(stranger).transferDevice(0, stranger.address))
        .to.be.revertedWithCustomError(manager, "NotDeviceOwner")
        .withArgs(0n, stranger.address);
      await expect(manager.connect(owner).transferDevice(0, ethers.ZeroAddress))
        .to.be.revertedWithCustomError(manager, "InvalidRecipient");
      await expect(manager.connect(owner).transferDevice(0, owner.address))
        .to.be.revertedWithCustomError(manager, "InvalidRecipient");
      await expect(manager.connect(stranger).updateFirmwareHash(0, ethers.ZeroHash))
        .to.be.revertedWithCustomError(manager, "NotDeviceOwner");
      await expect(manager.connect(owner).transferDevice(5, stranger.address))
        .to.be.revertedWithCustomError(manager, "DeviceNotFound");
    });

    it("updates properties and emits history events", async function () {
      const { manager, owner } = await loadFixture(deployFixture);
      const newKey = ethers.Wallet.createRandom();
      const newId = addressToIdentifier(newKey.address);
      await expect(manager.connect(owner).updateIdentifier(0, newId))
        .to.emit(manager, "DevicePropertyUpdated")
        .withArgs(0n, ethers.encodeBytes32String("identifier"), newId);
      expect(await manager.signerOf(0)).to.equal(newKey.address);

      const root = ethers.keccak256("0x01");
      await expect(manager.connect(owner).updateMetadataHash(0, root))
        .to.emit(manager, "DevicePropertyUpdated")
        .withArgs(0n, ethers.encodeBytes32String("metadata"), root);
    });

    it("keeps rotated identifiers reserved", async function () {
      const { manager, owner, stranger, identifier } = await loadFixture(deployFixture);
      await manager.connect(owner).updateIdentifier(0, addressToIdentifier(ethers.Wallet.createRandom().address));
      await expect(manager.connect(stranger).createDevice(identifier, ethers.ZeroHash, ethers.ZeroHash))
        .to.be.revertedWithCustomError(manager, "IdentifierAlreadyRegistered");
    });

    it("suspends, reactivates and revokes devices", async function () {
      const { manager, owner, manufacturer } = await loadFixture(deployFixture);
      await manager.connect(manufacturer).attestDevice(0, await future());

      await expect(manager.connect(owner).suspendDevice(0))
        .to.emit(manager, "DeviceStatusChanged")
        .withArgs(0n, Status.Active, Status.Suspended);
      expect(await manager.isActive(0)).to.equal(false);
      expect(await manager.isTrusted(0)).to.equal(false);
      await expect(manager.connect(owner).suspendDevice(0))
        .to.be.revertedWithCustomError(manager, "InvalidStatusTransition");

      await manager.connect(owner).reactivateDevice(0);
      expect(await manager.isTrusted(0)).to.equal(true);
      await expect(manager.connect(owner).reactivateDevice(0))
        .to.be.revertedWithCustomError(manager, "InvalidStatusTransition");

      await expect(manager.connect(owner).revokeDevice(0))
        .to.emit(manager, "DeviceStatusChanged")
        .withArgs(0n, Status.Active, Status.Revoked);
      expect(await manager.isAttestationValid(0)).to.equal(false);
    });

    it("blocks every change on a revoked device", async function () {
      const { manager, owner, buyer } = await loadFixture(deployFixture);
      await manager.connect(owner).revokeDevice(0);
      await expect(manager.connect(owner).revokeDevice(0)).to.be.revertedWithCustomError(manager, "DeviceIsRevoked");
      await expect(manager.connect(owner).reactivateDevice(0))
        .to.be.revertedWithCustomError(manager, "InvalidStatusTransition");
      await expect(manager.connect(owner).transferDevice(0, buyer.address))
        .to.be.revertedWithCustomError(manager, "DeviceIsRevoked");
      await expect(manager.connect(owner).updateFirmwareHash(0, ethers.ZeroHash))
        .to.be.revertedWithCustomError(manager, "DeviceIsRevoked");
    });
  });
});
