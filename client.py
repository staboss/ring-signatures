import time

from src.lsag.lsag_oop import *
from src.mlsag.mlsag_oop import *


def lsag_client():
    n = 10
    message = "LSAG signature"

    s_time = time.time()
    PK_set, sk, index = LSAG.key_generation(n)
    e_time = time.time()
    key_gen_time = e_time - s_time

    lsag = LSAG(message, n, PK_set)

    s_time = time.time()
    IK, c_value, s_vector = lsag.sign(sk, index)
    e_time = time.time()
    sign_time = e_time - s_time

    # lsag.message_bytes = str.encode("LSAG signaturе")
    s_time = time.time()
    is_valid = lsag.verify(IK, c_value, s_vector)
    e_time = time.time()
    verify_time = e_time - s_time

    print("Key generation         :", key_gen_time)
    print("Signature generation   :", sign_time)
    print("Signature verification :", verify_time)

    print("\nValidation: ", is_valid)

    return is_valid


def mlsag_client():
    n, m = 10, 5
    message = "MLSAG signature"

    s_time = time.time()
    PK_vectors, sk_vector, index = MLSAG.key_generation(n, m)
    e_time = time.time()
    key_gen_time = e_time - s_time

    mlsag = MLSAG(message, n, m, PK_vectors)

    s_time = time.time()
    IK_vector, c_value, s_vectors = mlsag.sign(sk_vector, index)
    e_time = time.time()
    sign_time = e_time - s_time

    # mlsag.message_bytes = str.encode("MLSAG signaturе")
    s_time = time.time()
    is_valid = mlsag.verify(IK_vector, c_value, s_vectors)
    e_time = time.time()
    verify_time = e_time - s_time

    print("Key generation         :", key_gen_time)
    print("Signature generation   :", sign_time)
    print("Signature verification :", verify_time)

    print("\nValidation: ", is_valid)

    return is_valid


if __name__ == '__main__':
    mlsag_client()
    # lsag_client()
