#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils


OP_0 = chr(0)

ADDR_PREFIX = chr(76)
SCRIPT_PREFIX = chr(16)

ADDR_PREFIX_TEST = chr(140)
SCRIPT_PREFIX_TEST = chr(19)


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
    # txid: 2c1ff1287ce0fc49412440de3a16bbc8bf7aaa810fe93577a4d9f07d142ef635
    # XiWWvBKa7H3AuYLc3fyKND8Taxn1b9FjkN
    print pubkey_to_legacy_address("02ad2d614dd811499d38d6db03a8355cb9fdba3dfa8f51d6735eca456edfb98d87")

    # txid: 086f193313292fb1ab60a2a927746edc29c81b8974ee755e75a081fa4f20de93
    # 7gQiswfdg5ms9Moq6JwxP8aYHc6XwHLv5G
    print redeemscript_to_p2sh_address("52210322021e68bfb69dcbf02dbf7fbb2bceca2a0321830acca1ea329d40d166c225b02102ace2135afad0893bd27384d4d5e2a2ad445c46530dbbda1639a401b2e6f223e6210200a8f2e32d534735622c1639530f15c23c9bfb5ac5a7a01293703f56a7a4d02e53ae")


if __name__ == "__main__":
    func_test()

