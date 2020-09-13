import time

from src.mlsag.mlsag_oop import MLSAG

message = "MLSAG signature"
m = 5

f = open("data/data_mlsag_core_i5.csv", "a")

for n in range(4, 101):
    s_time = time.time()
    PK_vectors, sk_vector, index = MLSAG.key_generation(n, m)
    e_time = time.time()
    key_gen_time = e_time - s_time

    mlsag = MLSAG(message, n, m, PK_vectors)

    s_time = time.time()
    IK_vector, c_value, s_vectors = mlsag.sign(sk_vector, index)
    e_time = time.time()
    sign_time = e_time - s_time

    s_time = time.time()
    is_valid = mlsag.verify(IK_vector, c_value, s_vectors)
    e_time = time.time()
    verify_time = e_time - s_time

    data = "{},{},{}\n".format(n, sign_time, verify_time)

    f.write(data)

f.close()
