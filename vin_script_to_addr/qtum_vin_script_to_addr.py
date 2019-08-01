#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils


OP_0 = chr(0)

ADDR_PREFIX = chr(58)
SCRIPT_PREFIX = chr(50)

ADDR_PREFIX_TEST = chr(120)
SCRIPT_PREFIX_TEST = chr(110)


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
    # txid: cd334d27d70cd21852091b0b3483a2461b2afd3dde360afa9bcff07de979f5b1
    # QaFPsZKqHAnfUrcQgRwVRuvk1T5QSvsRxC
    print pubkey_to_legacy_address("03fb554f55329a8f80b0aea3a60175a510d0ea9cf2b671d6c57371f73636a96ed3")

    # txid: ab8a9e5e182560f6360fc5adf6a88ffc908aa9d9b887aaae3cefbd393f286c7d
    # M9F1pAFeDKAG2b3CuJ2Ua9TChn9ue6SiB7
    print redeemscript_to_p2sh_address("5221025e219432b8fcda221fcff2bc236440e5eec66af2487eb9bf5c00194d2b0c86ae21028683e087ddf4244d952cbc6fb128a643add51e4458e049f70211a07a90a6fdbe2103a0e14dcb4e3b54cabb330a01f3fb55d6cb9294fe2ff7fad7dd8d449a1bbf48d653ae")


if __name__ == "__main__":
    func_test()

