import random

from Crypto.Hash import keccak

from src.ed25519 import *


def from_bytes(b):
    return int.from_bytes(b, sys.byteorder)


def field_value_gen(order=l):
    return random.randint(0, order - 1)


def matrix_gen(n, m):
    matrix = [None] * n
    for i in range(n):
        matrix[i] = [None] * m
    return matrix


def secret_key():
    return field_value_gen()


def public_key(sk):
    return point_mul(sk, G)


def keccak256(s):
    return keccak.new(digest_bits=256, data=s).digest()


def keccak256_mod_l(s):
    return from_bytes(keccak256(s)) % l


def point_hash(P):
    p = point_compress(P)
    h = from_bytes(keccak256(p))
    H = point_mul(h, G)
    return H


def scalar_hash(s):
    return keccak256_mod_l(s)


def combine_values(m, L, R):
    assert len(L) == len(R)

    res = m
    for i in range(len(L)):
        res += point_compress(L[i])
        res += point_compress(R[i])

    return res
