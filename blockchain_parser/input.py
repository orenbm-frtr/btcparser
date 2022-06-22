# Copyright (C) 2015-2016 The bitcoin-blockchain-parser developers
#
# This file is part of bitcoin-blockchain-parser.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of bitcoin-blockchain-parser, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

from .utils import decode_varint, decode_uint32, format_hash
from .script import Script
from .address import Address


class Input(object):
    """Represents a transaction input"""

    def __init__(self, raw_hex):
        self._transaction_hash = None
        self._script = None
        self._sequence_number = None
        self._witnesses = []
        self._addresses = None

        self._script_length, varint_length = decode_varint(raw_hex[36:])
        self._script_start = 36 + varint_length

        self.size = self._script_start + self._script_length + 4
        self.hex = raw_hex[:self.size]

    def add_witness(self, witness):
        self._witnesses.append(witness)

    @classmethod
    def from_hex(cls, hex_):
        return cls(hex_)

    def __repr__(self):
        return "'%s'" % (self.transaction_hash)

    @property
    def transaction_hash(self):
        """Returns the hash of the transaction containing the output
        redeemed by this input"""
        if self._transaction_hash is None:
            self._transaction_hash = format_hash(self.hex[:32])
        return self._transaction_hash

    @property
    def sequence_number(self):
        """Returns the input's sequence number"""
        if self._sequence_number is None:
            self._sequence_number = decode_uint32(
                self.hex[self.size-4:self.size]
            )
        return self._sequence_number

    @property
    def script(self):
        """Returns a Script object representing the redeem script"""
        if self._script is None:
            end = self._script_start + self._script_length
            self._script = Script.from_hex(self.hex[self._script_start:end])
        return self._script

    @property
    def witnesses(self):
        """Return a list of witness data attached to this input, empty if non segwit"""
        return self._witnesses
    
    @property
    def addresses(self):
        """Returns a list containing all the addresses mentioned
        in the input's script
        """
        if self._addresses is None:
            self._addresses = []
            if self.type == "pubkey":
                address = Address.from_public_key(self.script.operations[0])
                self._addresses.append(address)
            elif self.type == "pubkeyhash":
                address = Address.from_ripemd160(self.script.operations[2])
                self._addresses.append(address)
            elif self.type == "p2sh":
                address = Address.from_ripemd160(self.script.operations[1],
                                                 type="p2sh")
                self._addresses.append(address)
            elif self.type == "multisig":
                n = self.script.operations[-2]
                for operation in self.script.operations[1:1+n]:
                    self._addresses.append(Address.from_public_key(operation))
            elif self.type == "p2wpkh":
                address = Address.from_bech32(self.script.operations[1], 0)
                self._addresses.append(address)
            elif self.type == "p2wsh":
                address = Address.from_bech32(self.script.operations[1], 0)
                self._addresses.append(address)
