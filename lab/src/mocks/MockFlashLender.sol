// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockVoteToken.sol";

/**
 * @title MockFlashLender
 * @notice Flash loan lender for governance attacks.
 * @dev Calls receiver.onFlashLoan(address token, uint256 amount, bytes data).
 *      Matches the template IFlashLoan interface. Fee waived for clarity.
 */
contract MockFlashLender {
    MockVoteToken public token;
    uint256 public flashCount;

    bytes4 internal constant ON_FLASH_LOAN = bytes4(keccak256("onFlashLoan(address,uint256,bytes)"));

    event FlashLoan(address indexed receiver, uint256 amount);

    constructor(address _token) {
        token = MockVoteToken(_token);
    }

    function flashLoan(address receiver, address _token, uint256 amount, bytes calldata data) external {
        require(_token == address(token), "wrong token");
        uint256 actual = amount == type(uint256).max ? token.balanceOf(address(this)) : amount;
        require(actual > 0, "nothing to lend");

        token.transfer(receiver, actual);
        flashCount++;

        // invoke callback
        (bool ok,) = receiver.call(abi.encodeWithSelector(ON_FLASH_LOAN, address(token), actual, data));
        require(ok, "callback reverted");

        // require principal back (fee waived)
        require(token.balanceOf(address(this)) >= actual, "not repaid");
        emit FlashLoan(receiver, actual);
    }
}
