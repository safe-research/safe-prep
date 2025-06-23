// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

/// @title Safe EIP-7702 Proxy
/// @notice A delegation target compatible with the Safe smart account.
/// @dev This is a proxy contract that an EOA delegates to in order that ensures
///      a sane default setup for accounts.
contract Safe7702 {
    /// @dev The sentinel address value for the {_modules} and {_owners} linked
    ///      lists.
    address private constant _SENTINEL = address(0x1);

    /// @dev The default {Safe} singleton to proxy to.
    address private immutable _SINGLETON;

    /// @dev The {Safe} implementation address.
    address private $implementation;

    /// @dev The modules linked list.
    mapping(address => address) private $modules;

    /// @dev The owners linked list.
    mapping(address => address) private $owners;

    /// @dev A Safe proxy creation event, the event is emitted to simulate a
    ///      proxy deployment and trigger Safe transaction service indexing.
    event ProxyCreation(address indexed proxy, address implementation);

    /// @dev Safe owner was added.
    event AddedOwner(address indexed owner);

    /// @dev Safe owner was removed.
    event RemovedOwner(address indexed owner);

    constructor(address singleton) {
        _SINGLETON = singleton;
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }

    /// @notice Internal fallback implementation.
    function _fallback() private {
        address implementation = $implementation;
        if (implementation == address(0)) {
            implementation = _SINGLETON;
            if (msg.value == 0) {
                $implementation = implementation;
                _init(implementation);
                emit ProxyCreation(address(this), implementation);
            } else {
                (bool success, bytes memory result) = address(this).call("");
                _check(success, result);
            }
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let success := delegatecall(gas(), implementation, ptr, calldatasize(), 0, 0)
            returndatacopy(ptr, 0, returndatasize())
            switch success
            case 1 { return(ptr, returndatasize()) }
            default { revert(ptr, returndatasize()) }
        }
    }

    /// @notice Default account initialization.
    function _init(address implementation) private {
        // TODO(nlordell): Once safe-global/safe-smart-account#998 lands, we
        // will no longer have to do a "fake" `setup` and then emulate a
        // `swapOwner` to `address(this).

        address[] memory owners = new address[](1);
        {
            // TODO(nlordell): replace once #998 lands:
            //   owners[0] = address(this);
            owners[0] = address(0x2);
        }
        bytes memory setup = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            1,
            address(0),
            "",
            address(0),
            address(0),
            0,
            address(0)
        );

        (bool success, bytes memory result) = implementation.delegatecall(setup);
        _check(success, result);

        // TODO(nlordell): Fake an ownership change to the delegating EOA,
        // remove once #998 lands:
        {
            $owners[_SENTINEL] = address(this);
            $owners[address(this)] = _SENTINEL;
            $owners[address(0x2)] = address(0);
            emit RemovedOwner(address(0x2));
            emit AddedOwner(address(this));
        }
    }

    function _check(bool success, bytes memory result) private pure {
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
