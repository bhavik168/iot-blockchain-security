const { ethers } = require("ethers");

/**
 * Minimal Merkle tree with sorted-pair hashing, compatible with OpenZeppelin's MerkleProof.
 * Leaves are keccak256(abi.encodePacked(key, ":", value)) so a device can prove a single attribute
 * (e.g. "model:TH-200") without revealing the rest of its metadata.
 */
function hashPair(a, b) {
  return BigInt(a) < BigInt(b)
    ? ethers.keccak256(ethers.concat([a, b]))
    : ethers.keccak256(ethers.concat([b, a]));
}

function metadataLeaf(key, value) {
  return ethers.solidityPackedKeccak256(["string", "string", "string"], [key, ":", String(value)]);
}

class MetadataTree {
  /** @param {Record<string, string|number>} metadata */
  constructor(metadata) {
    this.entries = Object.entries(metadata);
    if (this.entries.length === 0) throw new Error("metadata must not be empty");
    this.leaves = this.entries.map(([k, v]) => metadataLeaf(k, v));
    this.layers = [this.leaves];
    while (this.layers[this.layers.length - 1].length > 1) {
      const prev = this.layers[this.layers.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        // An odd node is promoted to the next layer unchanged.
        next.push(i + 1 < prev.length ? hashPair(prev[i], prev[i + 1]) : prev[i]);
      }
      this.layers.push(next);
    }
  }

  get root() {
    return this.layers[this.layers.length - 1][0];
  }

  leaf(key) {
    const index = this.entries.findIndex(([k]) => k === key);
    if (index === -1) throw new Error(`unknown metadata key: ${key}`);
    return this.leaves[index];
  }

  proof(key) {
    let index = this.entries.findIndex(([k]) => k === key);
    if (index === -1) throw new Error(`unknown metadata key: ${key}`);
    const proof = [];
    for (let level = 0; level < this.layers.length - 1; level++) {
      const layer = this.layers[level];
      const sibling = index % 2 === 0 ? index + 1 : index - 1;
      if (sibling < layer.length) proof.push(layer[sibling]);
      index = Math.floor(index / 2);
    }
    return proof;
  }
}

/** "Hash of hash" of a firmware image, as stored on-chain. */
function firmwareCommitment(firmwareBytes) {
  return ethers.keccak256(ethers.keccak256(firmwareBytes));
}

/** Left-pads an Ethereum address into a bytes32 device identifier. */
function addressToIdentifier(address) {
  return ethers.zeroPadValue(address, 32);
}

module.exports = { MetadataTree, metadataLeaf, firmwareCommitment, addressToIdentifier };
