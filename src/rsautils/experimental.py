"""Experimental functions' module. Currently, covers: Non-Academic RSA

This module is the temporary home for any functions that are not yet finished or otherwise Work-In-Progress and are
not covered in specdoc.md as a "Core" function, but a stretch goal.
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
from rsautils.rsa import RSAPrivKey
from rsautils.rsa import RSAPubKey


class ExperimentalPubKey(RSAPubKey):
    """Experimental RSA Public Key.

    Implements all functions of the RSAPubKey class, with a set of overrides or extra functionality.
    Is not considered stable or at all finished.
    """
    pass


class ExperimentalPrivKey(RSAPrivKey):
    """Experimental RSA Private Key.

    Implements all functions of the RSAPrivKey class, with a set of overrides or extra functionality.
    Is not considered stable or at all finished.
    """
    pass
