from src.utils import *


def image_key(sk, PK):
    H = point_hash(PK)
    I = point_mul(sk, H)
    return I


def key_generation(n):
    """
    The key generation algorithm

    :param n: Number of users
    :return: Public keys, Secret key, Signer secret index
    """

    index = random.randint(0, n - 1)

    PK_set = [None for _ in range(n)]
    sk_set = [None for _ in range(n)]

    for i in range(n):
        sk_set[i] = secret_key()
        PK_set[i] = public_key(sk_set[i])

    return PK_set, sk_set[index], index


def lsag_generation(message, PK_set, sk, index):
    """
    The ring signature algorithm

    :param index: Signer secret index
    :param message: Secret message (bytes)
    :param PK_set: Public key set
    :param sk: Secret key

    :return: Image key and auxiliary values in order to be able to check the signature for correctness
    """

    n = len(PK_set)

    IK = image_key(sk, PK_set[index])

    L = [None for _ in range(n)]
    R = [None for _ in range(n)]
    s = [None for _ in range(n)]

    a = field_value_gen()
    c = [None for _ in range(n)]

    H = point_hash(PK_set[index])
    L[index] = point_mul(a, G)
    R[index] = point_mul(a, H)

    combined = combine_value(message, L[index], R[index])
    c[(index + 1) % n] = scalar_hash(combined)

    for _i in range(index + 1, n + index):
        i = _i % n
        P = PK_set[i]
        H = point_hash(P)
        s[i] = field_value_gen()
        L[i] = point_add(point_mul(s[i], G), point_mul(c[i], P))
        R[i] = point_add(point_mul(s[i], H), point_mul(c[i], IK))
        combined = combine_value(message, L[i], R[i])
        c[(i + 1) % n] = scalar_hash(combined)

    combined = combine_value(message, L[index - 1], R[index - 1])
    c[index] = scalar_hash(combined)

    s[index] = (a - c[index] * sk) % l

    return IK, c[0], s


def lsag_verification(message, PK_set, IK, c_value, s_vector):
    """
    The ring verification algorithm

    :param message: Secret message (bytes)
    :param PK_set: Public key set
    :param IK: Image key
    :param c_value: Auxiliary value
    :param s_vector: Auxiliary values

    :return: If the signature is valid or not
    """

    n = len(PK_set)

    L = [None for _ in range(n)]
    R = [None for _ in range(n)]
    c = [None for _ in range(n)]

    c[0] = c_value

    for i in range(n):
        P = PK_set[i]
        H = point_hash(P)
        s = s_vector[i]
        L[i] = point_add(point_mul(s, G), point_mul(c[i], P))
        R[i] = point_add(point_mul(s, H), point_mul(c[i], IK))
        combined = combine_value(message, L[i], R[i])
        c[(i + 1) % n] = scalar_hash(combined)

    return c[0] == c_value
