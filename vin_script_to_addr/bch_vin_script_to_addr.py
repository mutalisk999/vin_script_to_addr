#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils
from cashaddress.convert import to_cash_address


OP_0 = chr(0)

ADDR_PREFIX = chr(0)
SCRIPT_PREFIX = chr(5)

ADDR_PREFIX_TEST = chr(111)
SCRIPT_PREFIX_TEST = chr(196)


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
    return to_cash_address(base58.b58encode(d25))


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
    return to_cash_address(base58.b58encode(d25))


def func_test():
    # txid: 0207d9fa518322574ca44bb01f54c7f2cf181bf3ac221a51ccd284a70e6e4f10
    # qqz8aug6ac4ya0zjktpyudc8hgc8hyecvgaw9ewrj6
    print pubkey_to_legacy_address("03575e3f9c12728c9aa65b527c83b13a64fc0850a6d92aac15b8e4a72d28bbe31b")

    # txid: 1867f887a8f43dd4fc0252317e638c0bc39f01432f6cb02c508eb28680b4f1be
    # pzsee7v3sxg4sy5aghwzha5zulr9wkssackparnudp
    print redeemscript_to_p2sh_address("5221021cf422bc57a219c9bc12bc0fc6b21cce2b9915b935daa299757be812763e60562102f814785f896c735888012e178619155dd5c6451006e19a485a353f10d8f0583c2102e2bfeb7172cfe0d37514a563da38740f26996c067ec5177bfcc3857c9abde2ab53ae")


if __name__ == "__main__":
    func_test()

