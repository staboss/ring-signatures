from utils import *


def mlsag_secret_key():
    return field_value_gen()


def mlsag_public_key(secret_key):
    return point_mul(secret_key, G)


def mlsag_image_key(sk, PK):
    H = point_hash(PK)
    I = point_mul(sk, H)
    return I


def key_generation(n, m):
    """
    The  key  generation  algorithm

    :param n: Number of users
    :param m: Number of one-time addresses
    :return: Public key-vectors, Secret key-vector, Signer secret index
    """

    index = random.randint(0, n - 1)

    PK_vectors = matrix_gen(n, m)
    sk_vectors = matrix_gen(n, m)

    for i in range(n):
        for j in range(m):
            sk_vectors[i][j] = mlsag_secret_key()
            PK_vectors[i][j] = mlsag_public_key(sk_vectors[i][j])

    return PK_vectors, sk_vectors[index], index


def mlsag_generation(message, PK_vectors, sk_vector, index):
    """
    The  ring  signature  algorithm

    :param index: Signer secret index
    :param message: Secret message
    :param PK_vectors: Public key-vectors
    :param sk_vector: Secret key-vector

    :return: Image key-vector and auxiliary values in order to be able to check the signature for correctness
    """

    n = len(PK_vectors)
    m = len(PK_vectors[0])

    IK_vector = [mlsag_image_key(sk_vector[j], PK_vectors[index][j]) for j in range(m)]

    L = matrix_gen(n, m)
    R = matrix_gen(n, m)
    s = matrix_gen(n, m)

    a = [field_value_gen() for _ in range(m)]
    c = [None for _ in range(n)]

    for j in range(m):
        L[index][j] = point_mul(a[j], PK_vectors[index][j])

    for j in range(m):
        H = point_hash(PK_vectors[index][j])
        R[index][j] = point_mul(a[j], H)

    combined = combine_values(message, L[index], R[index])

    current_index = (index + 1) % n
    c[current_index] = scalar_hash(combined)

    for i in range(n):
        if i != index:
            for j in range(m):
                P = PK_vectors[i][j]
                H = point_hash(P)
                I = IK_vector[j]
                s[i][j] = field_value_gen()
                L[i][j] = point_mul(s[i][j], G) + point_mul(c[current_index], P)
                R[i][j] = point_mul(s[i][j], H) + point_mul(c[current_index], I)

            combined = combine_values(message, L[i], R[i])

            current_index = (current_index + 1) % n
            c[current_index] = scalar_hash(combined)

    combined = combine_values(message, L[index - 1], R[index - 1])
    c[index] = scalar_hash(combined)

    for j in range(m):
        s[index][j] = a[j] - (c[index] * sk_vector[j]) % l

    return IK_vector, c[0], s


def mlsag_verification(message, PK_vectors, IK_vector, c_value, s_vectors):
    """
    The  ring  verification  algorithm

    :param message: Secret message
    :param PK_vectors: Public key-vectors
    :param IK_vector: Image key-vector
    :param c_value: Auxiliary value
    :param s_vectors: Auxiliary values

    :return: If the signature is valid or not
    """

    n = len(PK_vectors)
    m = len(PK_vectors[0])

    L = matrix_gen(n, m)
    R = matrix_gen(n, m)

    c = [None for _ in range(n)]
    c[0] = c_value

    for i in range(0, n):
        for j in range(m):
            P = PK_vectors[i][j]
            H = point_hash(P)
            I = IK_vector[j]
            s = s_vectors[i][j]
            L[i][j] = point_mul(s, G) + point_mul(c[i], P)
            R[i][j] = point_mul(s, H) + point_mul(c[i], I)

        combined = combine_values(message, L[i], R[i])
        c[(i + 1) % n] = scalar_hash(combined)

    print(c[0])
    print(c_value)

    return c[0] == c_value
