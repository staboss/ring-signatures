import time

from src.lsag.lsag_oop import LSAG

message = "LSAG signature"

f = open("data_lsag.csv", "a")

for n in range(4, 101):
    s_time = time.time()
    PK_set, sk, index = LSAG.key_generation(n)
    e_time = time.time()
    key_gen_time = e_time - s_time

    mlsag = LSAG(message, n, PK_set)

    s_time = time.time()
    IK, c_value, s_vector = mlsag.sign(sk, index)
    e_time = time.time()
    sign_time = e_time - s_time

    s_time = time.time()
    is_valid = mlsag.verify(IK, c_value, s_vector)
    e_time = time.time()
    verify_time = e_time - s_time

    data = "{},{},{}\n".format(n, sign_time, verify_time)

    f.write(data)

f.close()
