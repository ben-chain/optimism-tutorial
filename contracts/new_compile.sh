#!/bin/bash

# TODO add opcodes that are not allowed
# and translate them to "invalid"
# and then check that it is not present
# in the optimized code.

#                "ovmCREATE(bytes)": "14aa2ff7",
#                "ovmCREATE2(bytes,bytes32)": "99ccd98b",
#                "ovmCREATEEOA(bytes32,uint8,bytes32,bytes32)": "741a33eb",
#                "ovmEXTCODECOPY(address,uint256,uint256)": "746c32f1",


HELPERS='
// This is "kall"
function ovm_callManager(arguments, arguments_size, output_area, output_area_size) {
    verbatim_4i_0o(
        hex"336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b",
        arguments,
        arguments_size,
        output_area,
        output_area_size
    )
}

function ovm_kopy(from, from_size, to, to_size) {
    verbatim_4i_0o(
        hex"3350600060045af1",
        from,
        from_size,
        to,
        to_size
    )
}

// Call a manager function with two arguments
function ovm_kall_2i(signature, x, y) {
    let tmp_a := mload(0x00)
    let tmp_b := mload(0x20)
    let tmp_c := mload(0x40)
    mstore(0, signature)
    mstore(4, x)
    mstore(0x24, y)
    ovm_callManager(0, 0x44, 0, 0)
    mstore(0x00, tmp_a)
    mstore(0x20, tmp_b)
    mstore(0x40, tmp_c)
}

// Call a manager function returning one value
function ovm_kall_1o(signature) -> r {
    let tmp_a := mload(0x00)
    mstore(0, signature)
    ovm_callManager(0, 4, 0, 0x20)
    r := mload(0)
    mstore(0, tmp_a)
}

// Call a manager function without arguments
function ovm_kall(signature) {
    let tmp_a := mload(0x00)
    mstore(0, signature)
    ovm_callManager(0, 4, 0, 0)
    mstore(0, tmp_a)
}


// Call a manager function with one argument and one return value
function ovm_kall_1i_1o(signature, x) -> r {
    let tmp_a := mload(0x00)
    let tmp_b := mload(0x20)
    mstore(0, signature)
    mstore(4, x)
    ovm_callManager(0, 0x24, 0, 0x20)
    r := mload(0)
    mstore(0x00, tmp_a)
    mstore(0x20, tmp_b)
}

function ovm_kall_dyn(signature, gasIn, addr, argsOffset, argsLength, retOffset, retLength) -> success {
    // TODO If the check fails, we have to use the MSIZE trick or move some
    // memory contents around.

    // Prepend data in front of the actual call data.
    let prefixSize := 0x84
    if iszero(argsLength) {
        // TODO we could do other optimizations.
        argsOffset := prefixSize
    }
    if lt(argsOffset, prefixSize) {
        // TODO find another way
        invalid()
    }

    let callBytes := sub(argsOffset, prefixSize)

    // save data in local variables before it is overwritten
    let tmp_a := mload(add(callBytes, 0x00))
    mstore(add(callBytes, 0), signature)
    let tmp_b := mload(add(callBytes, 0x20))
    let tmp_c := mload(add(callBytes, 0x40))
    mstore(add(callBytes, 0x04), gasIn)
    let tmp_d := mload(add(callBytes, 0x60))
    mstore(add(callBytes, 0x24), addr)
    let tmp_e := mload(add(callBytes, 0x80))
    mstore(add(callBytes, 0x44), 0x60)
    mstore(add(callBytes, 0x64), argsLength)

    // kall, only grabbing 3 words of returndata (success & abi encoding params) and just throw on top of where we put it (successfull kall will awlays return >= 0x60 bytes)
    // overpad calldata by a word (argsLen [raw data] + 0x84 [abi prefixing] + 0x20 [1 word max to pad] = argsLen + 0xa4) to ensure sufficient right 0-padding for abi encoding
    // TODO Properly right-pad, this needs another local variable, I think.
    ovm_callManager(callBytes, add(argsLength, prefixSize), callBytes, 0x60)

    // restore prefix
    mstore(add(callBytes, 0x80), tmp_e)
    mstore(add(callBytes, 0x60), tmp_d)
    mstore(add(callBytes, 0x20), tmp_b)
    let innerReturndatasize := mload(add(callBytes, 0x40))
    mstore(add(callBytes, 0x40), tmp_c)
    success := mload(callBytes)
    mstore(add(callBytes, 0x00), tmp_a)

    // write actual returned data
	returndatacopy(retOffset, 0x60, retLength)
	// call identity precompile to fix returndatasize
	ovm_kopy(0, innerReturndatasize, 0, innerReturndatasize)
}


function ovm_address() -> r {
    r := ovm_kall_1o(hex"996d79a5")
}

function ovm_call(gasIn, addr, value, argsOffset, argsLength, retOffset, retLength) -> success {
    success := ovm_kall_dyn("85979f76", gasIn, addr, argsOffset, argsLength, retOffset, retLength)
}

function ovm_staticcall(gasIn, addr, argsOffset, argsLength, retOffset, retLength) -> success {
    success := ovm_kall_dyn("8540661f", gasIn, addr, argsOffset, argsLength, retOffset, retLength)
}

function ovm_delegatecall(gasIn, addr, argsOffset, argsLength, retOffset, retLength) -> success {
    success := ovm_kall_dyn("ffe73914", gasIn, addr, argsOffset, argsLength, retOffset, retLength)
}

function ovm_caller() -> r {
    r := ovm_kall_1o(hex"73509064")
}

function ovm_callvalue() -> v {
    // we assume no Ether is sent
}

function ovm_chainid() -> r {
    r := ovm_kall_1o(hex"73509064")
}

function ovm_extcodehash(a) -> r {
    r := ovm_kall_1i_1o(hex"24749d5c", a)
}

function ovm_extcodesize(a) -> r {
    r := ovm_kall_1i_1o(hex"8435035b", a)
}

function ovm_gaslimit() -> r {
    r := ovm_kall_1o(hex"20160f3a")
}

// TODO where is this used?
function ovm_getnonce() -> r {
    r := ovm_kall_1o(hex"c1fb2ea2")
}

// TODO where is this used?
function ovm_incrementnonce() {
    ovm_kall(hex"7cebbe94")
}

function ovm_number() -> r {
    r := ovm_kall_1o(hex"5a98c361")
}

function ovm_revert(data, length) {
    let prefixSize := 0x64
    if iszero(length) {
        // TODO optimize further?
        data := prefixSize
    }
    let signature := "2a2a7adb"

    // TODO If the check fails, we have to use the MSIZE trick or move some
    // memory contents around.

    // Prepend data in front of the actual call data.
    if lt(data, prefixSize) {
        // TODO find another way
        invalid()
    }

    let callBytes := sub(data, prefixSize)

    mstore(add(callBytes, 0), signature)
    mstore(add(callBytes, 0x04), 0x20)
    mstore(add(callBytes, 0x24), length)
    ovm_callManager(callBytes, add(length, prefixSize), 0, 0)
    // the verbatim bytecode should revert.
    invalid()
}

function ovm_sload(s) -> r {
    r := ovm_kall_1i_1o(hex"03daa959", s)
}

function ovm_sstore(x, y) {
    ovm_kall_2i(hex"22bd64c0", x, y)
}

function ovm_timestamp() -> r {
    r := ovm_kall_1o(hex"bdbf8c36")
}

'

CODE=$(solc --ir "$1")
echo "compiled IR"
CODE=${CODE/IR:/}
for opcode in address call staticcall delegatecall caller callvalue chainid extcodesize extcodehash gaslimit number revert sload sstore timestamp
do
    echo "replacing opcode ${opcode}"
    # TODO we have to match a non-identifier in front of the opcode.
    CODE=${CODE//$opcode(/ovm_$opcode(}
    echo "replaced opcode ${opcode}"
done
echo "did replacement"
CODE=${CODE//code {/code {$HELPERS}
echo "$CODE"
echo "$CODE" | solc --strict-assembly --optimize --bin -
