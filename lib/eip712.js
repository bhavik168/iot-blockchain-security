/**
 * EIP-712 helpers shared by tests and scripts for SecureMessaging.
 */
const MESSAGE_TYPES = {
  DeviceMessage: [
    { name: "senderId", type: "uint256" },
    { name: "receiverId", type: "uint256" },
    { name: "payloadHash", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

const Verdict = {
  Valid: 0n,
  SenderInactive: 1n,
  ReceiverInactive: 2n,
  NotAuthorized: 3n,
  Expired: 4n,
  InvalidNonce: 5n,
  InvalidSignature: 6n,
};

const VERDICT_NAMES = Object.fromEntries(Object.entries(Verdict).map(([k, v]) => [v.toString(), k]));

async function messagingDomain(messaging) {
  const { chainId } = await messaging.runner.provider.getNetwork();
  return {
    name: "IoT SecureMessaging",
    version: "1",
    chainId,
    verifyingContract: await messaging.getAddress(),
  };
}

/**
 * Signs a DeviceMessage with the device wallet.
 * @returns {Promise<{message: object, signature: string}>}
 */
async function signDeviceMessage(messaging, deviceWallet, message) {
  const domain = await messagingDomain(messaging);
  const signature = await deviceWallet.signTypedData(domain, MESSAGE_TYPES, message);
  return { message, signature };
}

module.exports = { MESSAGE_TYPES, Verdict, VERDICT_NAMES, messagingDomain, signDeviceMessage };
