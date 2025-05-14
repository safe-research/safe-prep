// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {SafePREP} from "src/SafePREP.sol";
import {ISafe, SafeDeployments} from "./deployments/safe.sol";

contract CounterTest is Test {
    SafePREP public safePREP;
    ISafe public safeL2;

    function setUp() public {
        safePREP = new SafePREP();
        safeL2 = SafeDeployments.setUp(vm);
    }

    function test_Create() public {
        SafePREP.Setup memory setup = SafePREP.Setup({
            owners: new address[](1),
            threshold: 1,
            initializer: address(0),
            initializerData: "",
            fallbackHandler: address(0)
        });
        setup.owners[0] = address(this);

        (address account, uint256 salt, uint8 yParity, bytes32 r, bytes32 s) =
            safePREP.generateAccount(address(safeL2), setup, 42);
        assertEq(account.code.length, 0);

        uint256 chainId = block.chainid;
        vm.chainId(0);
        vm.attachDelegation(
            VmSafe.SignedDelegation({v: yParity, r: r, s: s, nonce: 0, implementation: address(safePREP)})
        );
        vm.chainId(chainId);

        assertGt(account.code.length, 0);

        SafePREP(payable(account)).setup7702(address(safeL2), setup, salt);

        bytes32 implementation = vm.load(account, bytes32(0));
        assertEq(implementation, bytes32(uint256(uint160(address(safeL2)))));

        address[] memory owners = ISafe(account).getOwners();
        assertEq(owners.length, 1);
        assertEq(owners[0], address(this));

        vm.deal(account, 1 ether);
        assertEq(account.balance, 1 ether);

        address target = address(0x7a29e7);
        assertEq(target.balance, 0);

        bytes memory signatures = abi.encodePacked(uint256(uint160(address(this))), uint256(0), uint8(1));
        ISafe(account).execTransaction(target, 1 ether, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures);
        assertEq(account.balance, 0);
        assertEq(target.balance, 1 ether);
    }

    function test_InitAuthorization() public {
        SafePREP.Setup memory setup = SafePREP.Setup({
            owners: new address[](1),
            threshold: 1,
            initializer: address(0),
            initializerData: "",
            fallbackHandler: address(0)
        });
        setup.owners[0] = address(0x7a29e7);

        (address account, uint256 salt, uint8 yParity, bytes32 r, bytes32 s) =
            safePREP.generateAccount(address(safeL2), setup, 42);

        uint256 chainId = block.chainid;
        vm.chainId(0);
        vm.attachDelegation(
            VmSafe.SignedDelegation({v: yParity, r: r, s: s, nonce: 0, implementation: address(safePREP)})
        );
        vm.chainId(chainId);

        vm.expectRevert(SafePREP.Unauthorized.selector);
        SafePREP(payable(account)).setup7702(address(this), setup, salt);

        vm.expectRevert(SafePREP.Unauthorized.selector);
        SafePREP(payable(account)).setup7702(address(safeL2), setup, salt + 1);

        setup.owners[0] = address(this);
        vm.expectRevert(SafePREP.Unauthorized.selector);
        SafePREP(payable(account)).setup7702(address(safeL2), setup, salt);
    }

    function test_SingletonMethods() public {
        SafePREP.Setup memory setup = SafePREP.Setup({
            owners: new address[](1),
            threshold: 1,
            initializer: address(0),
            initializerData: "",
            fallbackHandler: address(0xfa11bacc)
        });
        setup.owners[0] = address(this);

        (address account, uint256 salt, uint8 yParity, bytes32 r, bytes32 s) =
            safePREP.generateAccount(address(safeL2), setup, 42);

        uint256 chainId = block.chainid;
        vm.chainId(0);
        vm.attachDelegation(
            VmSafe.SignedDelegation({v: yParity, r: r, s: s, nonce: 0, implementation: address(safePREP)})
        );
        vm.chainId(chainId);

        bytes memory call;
        bool success;
        bytes memory result;

        call = abi.encodeCall(SafePREP.generateAccount, (address(safeL2), setup, salt));
        vm.expectCall(address(0), call);
        (success, result) = account.call(call);
        assertTrue(success && result.length == 0);

        SafePREP(payable(account)).setup7702(address(safeL2), setup, salt);

        call = abi.encodeCall(SafePREP.generateAccount, (address(safeL2), setup, salt));
        vm.expectCall(setup.fallbackHandler, abi.encodePacked(call, address(this)));
        (success, result) = account.call(call);
        assertTrue(success && result.length == 0);

        call = abi.encodeCall(SafePREP.generateAccount, (address(safeL2), setup, salt));
        vm.expectCall(setup.fallbackHandler, abi.encodePacked(call, address(this)));
        (success, result) = account.call(call);
        assertTrue(success && result.length == 0);
    }
}
