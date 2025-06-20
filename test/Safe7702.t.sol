// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test, Vm, console} from "forge-std/Test.sol";
import {Safe7702} from "src/Safe7702.sol";
import {ISafe, SafeDeployments} from "./deployments/safe.sol";

contract Safe7702Test is Test {
    ISafe public safeL2;
    Safe7702 public safe7702;
    Vm.Wallet public eoa;

    event SafeSetup(
        address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler
    );
    event ProxyCreation(address indexed proxy, address implementation);
    event SafeReceived(address indexed sender, uint256 value);

    function setUp() public {
        safeL2 = SafeDeployments.setUp(vm);
        safe7702 = new Safe7702(address(safeL2));
        eoa = vm.createWallet("kill the private key!");
    }

    function test_Setup() public {
        vm.signAndAttachDelegation(address(safe7702), eoa.privateKey);
        ISafe account = ISafe(payable(eoa.addr));

        // Calling view methods on the Safe reverts at first, because the
        // fallback implementation needs to `_setup` the account but cannot do
        // so in a static calling context.
        vm.expectRevert();
        account.getOwners();

        // Interacting with the account will cause it to setup though:
        vm.deal(address(this), 1 ether);
        {
            vm.expectEmit(true, false, false, true, eoa.addr);
            address[] memory o = new address[](1);
            o[0] = eoa.addr;
            emit SafeSetup(eoa.addr, o, 1, address(0), address(0));
        }
        {
            vm.expectEmit(true, false, false, true, eoa.addr);
            emit ProxyCreation(eoa.addr, address(safeL2));
        }
        {
            vm.expectEmit(true, false, false, true, eoa.addr);
            emit SafeReceived(address(this), 1 ether);
        }
        (bool success,) = eoa.addr.call{value: 1 ether}("");
        assertTrue(success);

        address[] memory owners = account.getOwners();
        assertEq(owners.length, 1);
        assertEq(owners[0], eoa.addr);

        // We can also sign transactions with the delegating EOA so that they
        // can be relayed by anyone.
        bytes32 transactionHash =
            account.getTransactionHash(address(this), 1 ether, "", 0, 0, 0, 0, address(0), address(0), account.nonce());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoa.privateKey, transactionHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertEq(address(account).balance, 1 ether);
        assertTrue(
            account.execTransaction(address(this), 1 ether, "", 0, 0, 0, 0, address(0), payable(address(0)), signature)
        );
        assertEq(address(account).balance, 0 ether);
    }

    receive() external payable {}
}
