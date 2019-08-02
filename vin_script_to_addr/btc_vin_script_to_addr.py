#!/usr/bin/env python
# -*- coding: utf-8 -*-


import base58
import utils
from bech32 import encode


OP_0 = chr(0)

ADDR_PREFIX = chr(0)
SCRIPT_PREFIX = chr(5)
BECH32_HRP = "bc"

ADDR_PREFIX_TEST = chr(111)
SCRIPT_PREFIX_TEST = chr(196)
BECH32_HRP_TEST = "tb"


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
    # txid: 620eb162e9b116290df4df7ccc4fb7cb79527a22f9303758ecf6ae65690ae1dd
    # 3HpUR2npzV2pSoVZMqrYVnoRMpBDLKitzX
    print witness_pubkey_to_p2sh_address("02ddff92509af9ef4ad0b73789d2b5a71bfeb8887558bcde1bb74023c119a27db4")

    # txid: 620eb162e9b116290df4df7ccc4fb7cb79527a22f9303758ecf6ae65690ae1dd
    # 3HpUR2npzV2pSoVZMqrYVnoRMpBDLKitzX
    print witness_p2wphk_script_to_p2sh_address("0014bf6e377083d77fa31d171481a0187f609b24ebc3")

    # txid: 620eb162e9b116290df4df7ccc4fb7cb79527a22f9303758ecf6ae65690ae1dd
    # 3HpUR2npzV2pSoVZMqrYVnoRMpBDLKitzX
    print witness_pubkey_to_bech32_address("02ddff92509af9ef4ad0b73789d2b5a71bfeb8887558bcde1bb74023c119a27db4")

    # txid: 620eb162e9b116290df4df7ccc4fb7cb79527a22f9303758ecf6ae65690ae1dd
    # 3HpUR2npzV2pSoVZMqrYVnoRMpBDLKitzX
    print witness_p2wphk_script_to_bech32_address("0014bf6e377083d77fa31d171481a0187f609b24ebc3")

    # txid: 9f64fadd37e2c62380ead74bf8641de67a7795d20f8b63ba62f4cfb490e8b0b8
    # 32BjLfja5eJ25bGCLFj3LVSDr8nB8cadPM
    # bc1qyy30guv6m5ez7ntj0ayr08u23w3k5s8vg3elmxdzlh8a3xskupyqn2lp5w
    print witness_redeemscript_to_p2sh_address(
        "5221022dfa322241a4946b9ead36ab9c8c55bd4c4340a1290b5bf71d23a695aeb1240a21034d82610a17c332852205e063c64fee21a77fabc7ac0e6d7ada2a820922c9a5dc2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae")

    # txid: 9f64fadd37e2c62380ead74bf8641de67a7795d20f8b63ba62f4cfb490e8b0b8
    # 32BjLfja5eJ25bGCLFj3LVSDr8nB8cadPM
    # bc1qyy30guv6m5ez7ntj0ayr08u23w3k5s8vg3elmxdzlh8a3xskupyqn2lp5w
    print witness_p2wsh_script_to_p2sh_address("00202122f4719add322f4d727f48379f8a8ba36a40ec4473fd99a2fdcfd89a16e048")

    # txid: 9f64fadd37e2c62380ead74bf8641de67a7795d20f8b63ba62f4cfb490e8b0b8
    # 32BjLfja5eJ25bGCLFj3LVSDr8nB8cadPM
    # bc1qyy30guv6m5ez7ntj0ayr08u23w3k5s8vg3elmxdzlh8a3xskupyqn2lp5w
    print witness_redeemscript_to_bech32_address("5221022dfa322241a4946b9ead36ab9c8c55bd4c4340a1290b5bf71d23a695aeb1240a21034d82610a17c332852205e063c64fee21a77fabc7ac0e6d7ada2a820922c9a5dc2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae")

    # txid: 9f64fadd37e2c62380ead74bf8641de67a7795d20f8b63ba62f4cfb490e8b0b8
    # 32BjLfja5eJ25bGCLFj3LVSDr8nB8cadPM
    # bc1qyy30guv6m5ez7ntj0ayr08u23w3k5s8vg3elmxdzlh8a3xskupyqn2lp5w
    print witness_p2wsh_script_to_bech32_address("00202122f4719add322f4d727f48379f8a8ba36a40ec4473fd99a2fdcfd89a16e048")

    # txid: 325308822948fbe9beb4d9364b64c0f0938dcc601a09bad92f0aba20ee2b8eff
    # 15bd19ToWr4TY9XsQkTT5rKTafwscZLDud
    print pubkey_to_legacy_address("02c7ea8bd4d361838ac3cefd9aaf9df5051b4f0a22ae51a9d7f4fd84ed92aca5c2")

    # txid: f99a904f8be091ad5c2d96879ed13b06decc5288e03f25c49b92e0a159b8a1ab
    # 3CYgPrrvvmhaZDG6sYe8j8Xpiz8ZFQd9SH
    print redeemscript_to_p2sh_address(
        "5b210209f45f7adb48d3a2bcc62ab49a29df822fdaf6b2c1e26afc48529a6a4272240c21023a37b1ec16f5d073ed4c1c435ac0dad2031f2d0188d439a5655b3bd1e8d9f0d72103a9e498958e3b816c89a6886adadc65a67e3658dfbc0c2a8d898536a64bb14ee22103d99a8ac95d78488394f0611bf3a654a726bb47b1453ed8ba93a26a868419c858210276447b1c51823c89359b64ae03ce23497caee8e4a3ce0b0616b18102c2f909122103b935a588f8d1f38af0926ba8b32fa4d2f549e97129544852922a45d4853b9a7e2103a154c3e59040df072d6a82a322a8cc48c142f85745749bb4147dfb0265a3c7382102bdbdb15ab4495025990f99edb7ab29f1fed3ae10b6631a7aa0a837053273cbb421039bf0b4f48b33456fca71f541143a5b4c0195e138ccc51ef71d1d4c25a8c3258a2102a7822cd38afae7a31cf8f5443c91c877d1931aeb58bd319fa7c95a7666bb07852102d23df29f6c723e0ea71b9841c010e18011462ec03a709e8fbd9c1e5ae89967e82103d4abf1bc7e68724f6773fc7540e0b6c824f8cdb1277686cf882f2fd9c67dec24210264bda4f2a7df256bea73e4c1dcb1e0a5025f6c8d4a796a05b94f96dcbdf6934d2103d15ebcf0b728a88422e73da8dda85d20a5c54695884d0f6c6b49caeeb783456e2103370fe3bc506e3ea8f233329c0fcbb7869b937b5a5810815b548d3fc7e4321f995fae")


if __name__ == "__main__":
    func_test()

