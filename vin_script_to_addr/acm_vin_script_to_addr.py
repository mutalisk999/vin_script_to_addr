#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils
from bech32 import encode


OP_0 = chr(0)

ADDR_PREFIX = chr(53)
SCRIPT_PREFIX = chr(55)
BECH32_HRP = "acm"

ADDR_PREFIX_TEST = chr(43)
SCRIPT_PREFIX_TEST = chr(58)
BECH32_HRP_TEST = "tacm"


# p2wpkh segwit
def witness_pubkey_to_p2sh_address(pubkey, main_net=True):
    pubkey = pubkey.decode("hex")
    d20 = utils.hash160(pubkey)
    witness_script = OP_0 + chr(len(d20)) + d20

    script_prefix = SCRIPT_PREFIX
    if not main_net:
        script_prefix = SCRIPT_PREFIX_TEST

    h20 = utils.hash160(witness_script)
    d21 = script_prefix + h20
    c4 = utils.checksum(d21)

    d25 = d21 + c4
    return base58.b58encode(d25)


def witness_p2wphk_script_to_p2sh_address(p2wphk_script, main_net=True):
    witness_script = p2wphk_script.decode("hex")

    script_prefix = SCRIPT_PREFIX
    if not main_net:
        script_prefix = SCRIPT_PREFIX_TEST

    h20 = utils.hash160(witness_script)
    d21 = script_prefix + h20
    c4 = utils.checksum(d21)

    d25 = d21 + c4
    return base58.b58encode(d25)


def witness_pubkey_to_bech32_address(pubkey, main_net=True):
    pubkey = pubkey.decode("hex")
    d20 = utils.hash160(pubkey)
    witness_script = OP_0 + chr(len(d20)) + d20

    hrp = BECH32_HRP
    if not main_net:
        hrp = BECH32_HRP_TEST

    witness_script_bytes = [ord(c) for c in witness_script]
    return encode(hrp, witness_script_bytes[0], witness_script_bytes[2:])


def witness_p2wphk_script_to_bech32_address(p2wphk_script, main_net=True):
    witness_script = p2wphk_script.decode("hex")

    hrp = BECH32_HRP
    if not main_net:
        hrp = BECH32_HRP_TEST

    witness_script_bytes = [ord(c) for c in witness_script]
    return encode(hrp, witness_script_bytes[0], witness_script_bytes[2:])


# p2wsh segwit
def witness_redeemscript_to_p2sh_address(redeemscript, main_net=True):
    redeemscript = redeemscript.decode("hex")
    d32 = utils.sha256(redeemscript)
    witness_script = OP_0 + chr(len(d32)) + d32

    script_prefix = SCRIPT_PREFIX
    if not main_net:
        script_prefix = SCRIPT_PREFIX_TEST

    h20 = utils.hash160(witness_script)
    d21 = script_prefix + h20
    c4 = utils.checksum(d21)

    d25 = d21 + c4
    return base58.b58encode(d25)


def witness_p2wsh_script_to_p2sh_address(p2wsh_script, main_net=True):
    witness_script = p2wsh_script.decode("hex")

    script_prefix = SCRIPT_PREFIX
    if not main_net:
        script_prefix = SCRIPT_PREFIX_TEST

    h20 = utils.hash160(witness_script)
    d21 = script_prefix + h20
    c4 = utils.checksum(d21)

    d25 = d21 + c4
    return base58.b58encode(d25)


def witness_redeemscript_to_bech32_address(redeemscript, main_net=True):
    redeemscript = redeemscript.decode("hex")
    d32 = utils.sha256(redeemscript)
    witness_script = OP_0 + chr(len(d32)) + d32

    hrp = BECH32_HRP
    if not main_net:
        hrp = BECH32_HRP_TEST

    witness_script_bytes = [ord(c) for c in witness_script]
    return encode(hrp, witness_script_bytes[0], witness_script_bytes[2:])


def witness_p2wsh_script_to_bech32_address(p2wsh_script, main_net=True):
    witness_script = p2wsh_script.decode("hex")

    hrp = BECH32_HRP
    if not main_net:
        hrp = BECH32_HRP_TEST

    witness_script_bytes = [ord(c) for c in witness_script]
    return encode(hrp, witness_script_bytes[0], witness_script_bytes[2:])


# p2pkh
def pubkey_to_legacy_address(pubkey, main_net=True):
    pubkey = pubkey.decode("hex")

    addr_prefix = ADDR_PREFIX
    if not main_net:
        addr_prefix = ADDR_PREFIX_TEST

    h20 = utils.hash160(pubkey)
    d21 = addr_prefix + h20
    c4 = utils.checksum(d21)

    d25 = d21 + c4
    return base58.b58encode(d25)


# p2sh
def redeemscript_to_p2sh_address(redeem_script, main_net=True):
    redeem_script = redeem_script.decode("hex")

    script_prefix = SCRIPT_PREFIX
    if not main_net:
        script_prefix = SCRIPT_PREFIX_TEST

    h20 = utils.hash160(redeem_script)
    d21 = script_prefix + h20
    c4 = utils.checksum(d21)

    d25 = d21 + c4
    return base58.b58encode(d25)


def func_test():
    # txid:
    #
    print witness_pubkey_to_p2sh_address("")

    # txid:
    #
    print witness_p2wphk_script_to_p2sh_address("")

    # txid:
    #
    print witness_pubkey_to_bech32_address("")

    # txid:
    #
    # print witness_p2wphk_script_to_bech32_address("")

    # txid:
    #
    #
    print witness_redeemscript_to_p2sh_address(
        "")

    # txid:
    #
    #
    print witness_p2wsh_script_to_p2sh_address("")

    # txid:
    #
    #
    print witness_redeemscript_to_bech32_address("")

    # txid:
    #
    #
    # print witness_p2wsh_script_to_bech32_address("")

    # txid:
    #
    print pubkey_to_legacy_address("02c3bc583711982937301fe0e556ec1c2024170a8ec40a04b6e047f8b99ad7a252")

    # txid:
    #
    print redeemscript_to_p2sh_address(
        "")


if __name__ == "__main__":
    func_test()

