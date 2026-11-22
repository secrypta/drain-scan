// SPDX-License-Identifier: MIT
// PROVENANCE: authored synthetic toy (NOT a real incident). First-party drain-scan fixture.
// Companion to DeclaredNonceIgnoredSettlement.sol: the SAME settlement contract with the nonce
// actually ENFORCED. The nonce is (a) checked against stored state AND consumed (incremented),
// and (b) woven into the signed digest. This is a genuine safe control: R5 must stay SILENT.
pragma solidity 0.8.24;

contract EnforcedNonceSettlement {
    bytes32 public immutable DOMAIN_SEPARATOR;

    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balanceOf;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode("EnforcedNonceSettlement", block.chainid, address(this)));
    }

    function settle(address owner, address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        // (a) check the nonce against stored state...
        require(nonce == nonces[owner], "bad nonce");
        // ...and (b) bind it into the signed digest.
        bytes32 structHash = keccak256(abi.encode(to, amount, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner && signer != address(0), "bad sig");

        // ...and consume it, so the signature cannot be replayed.
        nonces[owner] += 1;

        balanceOf[owner] -= amount;
        balanceOf[to] += amount;
    }
}
