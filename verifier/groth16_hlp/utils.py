#!/usr/bin/env python3

# AlexZ: This code is entirly based on the utils.py from Zeth
#        Just stripping some code to reduce the dependencies...
#        /snarks/depends/zeth/client/zeth/core/utils.py

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from typing import Sequence, List, Tuple, Union, Iterable, Any, Optional, cast


def string_list_flatten(str_list: Sequence[Union[str, List[str]]]) -> List[str]:
    """
    Flatten a list containing strings or lists of strings.
    """
    if any(isinstance(el, (list, tuple)) for el in str_list):
        strs: List[str] = []
        for el in str_list:
            if isinstance(el, (list, tuple)):
                strs.extend(el)
            else:
                strs.append(cast(str, el))
        return strs

    return cast(List[str], str_list)


def hex_to_uint256_list(hex_str: str) -> Iterable[int]:
    """
    Given a hex string of arbitrary size, split into uint256 ints, left padding
    with 0s.
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    assert len(hex_str) % 2 == 0
    start_idx = 0
    next_idx = len(hex_str) - int((len(hex_str) - 1) / 64) * 64
    while next_idx <= len(hex_str):
        sub_str = hex_str[start_idx:next_idx]
        yield int(sub_str, 16)
        start_idx = next_idx
        next_idx = next_idx + 64

def hex_list_to_uint256_list(
        elements: Sequence[Union[str, List[str]]]) -> List[int]:
    """
    Given an array of hex strings, return an array of int values by converting
    each hex string to evm uint256 words, and flattening the final list.
    """
    # In reality, we need to cope with lists of lists, to handle all
    # field extension degrees for all curve coordinate types.
    # TODO: Create a new type to describe this safely.
    flat_elements = string_list_flatten(elements)
    return [i for hex_str in flat_elements for i in hex_to_uint256_list(hex_str)]

def int_and_bytelen_from_hex(value_hex: str) -> Tuple[int, int]:
    """
    Decode prefixed / non-prefixed hex string and extract the length in bytes
    as well as the value.
    """
    assert len(value_hex) % 2 == 0
    if value_hex.startswith("0x"):
        num_bytes = int((len(value_hex) - 2) / 2)
    else:
        num_bytes = int(len(value_hex) / 2)
    return (int(value_hex, 16), num_bytes)


def int_to_hex(value: int, num_bytes: int) -> str:
    """
    Create prefixed hex string enforcing a specific byte-length.
    """
    return "0x" + value.to_bytes(num_bytes, byteorder='big').hex()

