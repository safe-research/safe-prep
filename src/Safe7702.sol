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
    address private _implementation;

    /// @dev The modules linked list.
    mapping(address => address) private _modules;

    /// @dev The owners linked list.
    mapping(address => address) private _owners;

    /// @dev The owner count.
    uint256 private _ownerCount;

    /// @dev The signer threshold.
    uint256 private _threshold;

    /// @dev A Safe setup event, the event is emitted to simulate a Safe setup
    ///      and trigger Safe transaction service indexing.
    event SafeSetup(
        address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler
    );

    /// @dev A Safe proxy creation event, the event is emitted to simulate a
    ///      proxy deployment and trigger Safe transaction service indexing.
    event ProxyCreation(address indexed proxy, address implementation);

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
        address implementation = _implementation;
        if (implementation == address(0)) {
            implementation = _SINGLETON;
            _implementation = implementation;
            _setup();
            emit ProxyCreation(address(this), implementation);
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

    /// @notice Default setup implementation.
    function _setup() private {
        // TODO(nlordell): Once safe-global/safe-smart-account#998 lands, this
        // function should be implemented as (pseudocode):
        //
        //        _SINGLETON.delegatecall(abi.encodeWithSignature(
        //            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
        //            [address(this)],
        //            1,
        //            address(0),
        //            "",
        //            address(0),
        //            address(0),
        //            0,
        //            payable(address(0))
        //        ));

        _modules[_SENTINEL] = _SENTINEL;
        _owners[_SENTINEL] = address(this);
        _owners[address(this)] = _SENTINEL;
        _ownerCount = 1;
        _threshold = 1;

        address[] memory owners = new address[](1);
        owners[0] = address(this);
        emit SafeSetup(address(this), owners, 1, address(0), address(0));
    }
}
