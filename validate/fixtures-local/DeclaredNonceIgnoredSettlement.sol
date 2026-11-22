// SPDX-License-Identifier: MIT
// PROVENANCE: authored synthetic toy (NOT a real incident). First-party drain-scan fixture.
// Purpose: prove R5's ENFORCEMENT-based nonce axis. This contract VERIFIES an EIP-712-style
// signature (domain separator present, so R5's domain axis is satisfied) and DECLARES a
// per-owner `nonces` mapping -- but never checks it, never consumes it, and never binds it into
// the signed digest. The same signature therefore settles forever: a replayable drain.
//
// Under the OLD declaration-based R5 (nonce counted as present if a `nonce`-named declaration
// exists anywhere), this was a FALSE NEGATIVE (R5 stayed silent). Under the enforcement-based
// R5 it is correctly flagged VULNERABLE (replayable).
pragma solidity 0.8.24;

contract DeclaredNonceIgnoredSettlement {
    bytes32 public immutable DOMAIN_SEPARATOR;

    // Declared replay-protection state -- but nothing below ever reads, compares, increments,
    // or signs over it. Dead state; the signature stays valid across unlimited settlements.
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public balanceOf;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode("DeclaredNonceIgnoredSettlement", block.chainid, address(this)));
    }

    // owner signs (to, amount). The digest binds the domain and the transfer fields -- but NOT
    // the nonce. Replaying the identical (owner, to, amount, v, r, s) drains `owner` again.
    function settle(address owner, address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 structHash = keccak256(abi.encode(to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner && signer != address(0), "bad sig");

        balanceOf[owner] -= amount;
        balanceOf[to] += amount;
    }
}
