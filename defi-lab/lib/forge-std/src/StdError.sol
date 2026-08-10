// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library stdError {
    bytes internal constant arithmeticError = abi.encodeWithSignature("Error(string)", "arithmetic error");
    bytes internal constant assertionError = abi.encodeWithSignature("Error(string)", "assertion error");
    bytes internal constant divisionError = abi.encodeWithSignature("Error(string)", "division by zero");
    bytes internal constant encodeStorageError = abi.encodeWithSignature("Error(string)", "encode storage error");
    bytes internal constant popError = abi.encodeWithSignature("Error(string)", "pop from empty array");
    bytes internal constant indexOobError = abi.encodeWithSignature("Error(string)", "index out of bounds");
    bytes internal constant enumConversionError = abi.encodeWithSignature("Error(string)", "enum conversion error");
    bytes internal constant zeroVarError = abi.encodeWithSignature("Error(string)", "zero variable error");
}
