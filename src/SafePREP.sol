// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

/// @title Safe EIP-7702 PREP
/// @notice A PREP delegation target compatible with the Safe smart account.
/// @dev At its core, {SafePREP} is a proxy contract that is intended to be an
///      EIP-7702 PREP delegation target.
/// @custom:reference https://blog.biconomy.io/prep-deep-dive/
contract SafePREP {
    /// @dev Safe PREP setup parameters.
    struct Setup {
        address[] owners;
        uint256 threshold;
        address initializer;
        bytes initializerData;
        address fallbackHandler;
    }

    /// @dev Fixed ECDSA signature S value for the EIP-7702 authorization.
    bytes32 private constant _S = bytes32(uint256(keccak256("PREP")) - 1);

    /// @dev Fixed ECDSA signature V value for the EIP-7702 authorization.
    uint8 private constant _V = 27;

    /// @dev Fixed ECDSA signature Y-parity for the EIP-7702 authorization.
    uint8 private constant _Y_PARITY = _V - 27;

    /// @dev The {SafePREP} contract address.
    address private immutable _SELF;

    /// @dev The EIP-7702 authorization message for delegating to this contract.
    bytes32 private immutable _AUTHORIZATION;

    /// @dev The {Safe} implementation address.
    address private _implementation;

    /// @dev A Safe proxy creation event, the event is emitted to simulate a
    ///      proxy deployment and trigger Safe transaction service indexing.
    event ProxyCreation(address indexed proxy, address implementation);

    /// @notice Unauthorized setup.
    error Unauthorized();

    constructor() {
        _SELF = address(this);
        _AUTHORIZATION = _authorization();
    }

    /// @notice Function only callable if the account is uninitalized.
    /// @dev This will cause a function to be called when the account has no
    ///      {Safe} implementation set, otherwise it will fallback to its
    ///      implementation.
    modifier onlyUninitialized() {
        address implementation = _implementation;
        if (implementation != address(0)) {
            _fallback(implementation);
        } else {
            _;
        }
    }

    /// @notice Function only callable on the {SafePREP} contract itself.
    /// @dev This will cause a function to be called on the {SafePREP} contract
    ///      itself, but will delegate to its {_implementation} when called as
    ///      an EIP-7702 delegation target. This allows the {SafePREP} contract
    ///      to implement helper functions, without affecting accounts.
    modifier onlySelf() {
        if (address(this) != _SELF) {
            _fallback(_implementation);
        } else {
            _;
        }
    }

    fallback() external payable {
        _fallback(_implementation);
    }

    receive() external payable {
        _fallback(_implementation);
    }

    function setup7702(address implementation, Setup calldata setup, uint256 salt) external onlyUninitialized {
        (bytes32 initHash, bytes memory init) = _init(implementation, setup);
        (address account,) = _prep(initHash, salt);
        require(account == address(this), Unauthorized());

        _implementation = implementation;
        assembly ("memory-safe") {
            if iszero(delegatecall(gas(), implementation, add(init, 0x20), mload(init), 0, 0)) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }

        emit ProxyCreation(address(this), implementation);
    }

    function generateAccount(address implementation, Setup calldata setup, uint256 startingSalt)
        external
        onlySelf
        returns (address account, uint256 salt, uint8 yParity, bytes32 r, bytes32 s)
    {
        (bytes32 initHash,) = _init(implementation, setup);
        salt = startingSalt;
        (account, r) = _prep(initHash, salt);
        while (account == address(0)) {
            salt++;
            (account, r) = _prep(initHash, salt);
        }
        return (account, salt, _Y_PARITY, r, _S);
    }

    function _fallback(address implementation) private {
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

    function _authorization() internal view returns (bytes32 authorization) {
        uint8 addressLength = 20;
        bytes20 addressBits = bytes20(address(this));
        while (bytes1(addressBits) == 0) {
            addressLength--;
            addressBits = addressBits << 8;
        }

        bytes memory addressBytes = abi.encode(addressBits);
        assembly ("memory-safe") {
            mstore(addressBytes, addressLength)
        }

        return keccak256(
            abi.encodePacked(
                uint8(0x05), // MAGIC
                uint8(0xc3) + addressLength, // RLP list
                uint8(0x80), // chainid = 0
                uint8(0x80) + addressLength,
                addressBytes,
                uint8(0x80) // nonce = 0
            )
        );
    }

    function _init(address implementation, Setup memory setup)
        internal
        pure
        returns (bytes32 initHash, bytes memory init)
    {
        init = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            setup.owners,
            setup.threshold,
            setup.initializer,
            setup.initializerData,
            setup.fallbackHandler,
            address(0),
            0,
            payable(address(0))
        );
        initHash = keccak256(abi.encode(implementation, keccak256(init)));
        return (initHash, init);
    }

    function _prep(bytes32 initHash, uint256 salt) internal view returns (address account, bytes32 r) {
        r = keccak256(abi.encode(initHash, salt));
        account = ecrecover(_AUTHORIZATION, _V, r, _S);
        return (account, r);
    }
}
