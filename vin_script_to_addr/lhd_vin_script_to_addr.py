#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils


OP_0 = chr(0)

SCRIPT_PREFIX = chr(5)

SCRIPT_PREFIX_TEST = chr(196)


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


def func_test():
    # txid: 3b29c24a81474288c1363d5ec4c8273ba9e00c8eb735b5767cdaf5c2c269c800
    # 363BpGH9mYokbu5dDHgUoUfBusm75Mjf3B
    print witness_pubkey_to_p2sh_address("030938b730295de2fa5c76c8fb0236b874aa8aac72a52e9e9cbd51ed210a0a2257")

    # txid: 3b29c24a81474288c1363d5ec4c8273ba9e00c8eb735b5767cdaf5c2c269c800
    # 363BpGH9mYokbu5dDHgUoUfBusm75Mjf3B
    print witness_p2wphk_script_to_p2sh_address("0014529b1f3a3bc522e7e67f783c51ebd18f41f5e07e")

    # txid:
    #
    # print witness_redeemscript_to_p2sh_address("")

    # txid:
    #
    # print witness_p2wsh_script_to_p2sh_address("")


if __name__ == "__main__":
    func_test()

