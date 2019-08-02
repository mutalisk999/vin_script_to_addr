#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils


OP_0 = chr(0)

ADDR_PREFIX = chr(48)
SCRIPT_PREFIX = chr(50)

ADDR_PREFIX_TEST = chr(111)
SCRIPT_PREFIX_TEST = chr(58)


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
    # txid: 80dd9674beaee5270f8f4bccae31e7d62bb9c303df444def555a3618c32b1f36
    # MN4zm1U7eMdaawUWFY9mBpkU9ZJef19Yei
    # print witness_pubkey_to_p2sh_address("")

    # txid: 80dd9674beaee5270f8f4bccae31e7d62bb9c303df444def555a3618c32b1f36
    # MN4zm1U7eMdaawUWFY9mBpkU9ZJef19Yei
    print witness_p2wphk_script_to_p2sh_address("0014564587ebe95fcc0ee0a188bf10f8b8a76b5fedf3")

    # txid:
    #
    # print witness_redeemscript_to_p2sh_address("")

    # txid:
    #
    # print witness_p2wsh_script_to_p2sh_address("")

    # txid: 307e43a772dd987b07d446b87e17140aa75e2c7820d025c6b48c9a10c842b1fd
    # LdqpyoKnmDnWt2skVnVa1mtHMpRoJyuBNj
    print pubkey_to_legacy_address("02bffd7b454ac55aaaebc60124b9d9025b0badd0e4b63076079cd5a3474cbca776")

    # txid: 7477d6595a5c97aabae76a2f485e0687bd5c2deca15bf7e62d67c2655fc9616c
    # MG5tQZZhrCevWKdekvHoakyZVH3qNDu6XL
    print redeemscript_to_p2sh_address(
        "522103479d5241f74d88bf705b5b0426c6d0882beb4189d4ce1699133be41ee07ecdae2103450b3a12eb64c35dae830cfbd409e7a660e07b85200f6fcf70ae209874898b21210366621131861355f4d440757d40f470260670e9b03a1e573091e73cfbf32f0ea253ae")


if __name__ == "__main__":
    func_test()

