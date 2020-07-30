from src.utils import *


class LSAG:
    """
    Linkable Spontaneous Anonymous Group (MLSAG) signature
    is a ring signature over a set of n users
    """

    def __init__(self, message, number_of_users, PK_set):
        """
        :param message: Secret message (bytes)
        :param number_of_users: Number of users
        :param PK_set: Public key set
        """
        self.n = number_of_users
        self.PK_set = PK_set
        self.message_bytes = str.encode(message)

    @staticmethod
    def image_key(sk, PK):
        H = point_hash(PK)
        I = point_mul(sk, H)
        return I

    @staticmethod
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

    def sign(self, sk, index):
        """
        The ring signature algorithm

        :param index: Signer secret index
        :param sk: Secret key

        :return: Image key and auxiliary values in order to be able to check the signature for correctness
        """

        IK = self.image_key(sk, self.PK_set[index])

        L = [None for _ in range(self.n)]
        R = [None for _ in range(self.n)]
        s = [None for _ in range(self.n)]

        a = field_value_gen()
        c = [None for _ in range(self.n)]

        H = point_hash(self.PK_set[index])
        L[index] = point_mul(a, G)
        R[index] = point_mul(a, H)

        combined = combine_value(self.message_bytes, L[index], R[index])
        c[(index + 1) % self.n] = scalar_hash(combined)

        for _i in range(index + 1, self.n + index):
            i = _i % self.n
            P = self.PK_set[i]
            H = point_hash(P)
            s[i] = field_value_gen()
            L[i] = point_add(point_mul(s[i], G), point_mul(c[i], P))
            R[i] = point_add(point_mul(s[i], H), point_mul(c[i], IK))
            combined = combine_value(self.message_bytes, L[i], R[i])
            c[(i + 1) % self.n] = scalar_hash(combined)

        combined = combine_value(self.message_bytes, L[index - 1], R[index - 1])
        c[index] = scalar_hash(combined)

        s[index] = (a - c[index] * sk) % l

        return IK, c[0], s

    def verify(self, IK, c_value, s_vector):
        """
        The ring verification algorithm

        :param IK: Image key
        :param c_value: Auxiliary value
        :param s_vector: Auxiliary values

        :return: If the signature is valid or not
        """

        L = [None for _ in range(self.n)]
        R = [None for _ in range(self.n)]

        c = [None for _ in range(self.n)]
        c[0] = c_value

        for i in range(self.n):
            P = self.PK_set[i]
            H = point_hash(P)
            s = s_vector[i]
            L[i] = point_add(point_mul(s, G), point_mul(c[i], P))
            R[i] = point_add(point_mul(s, H), point_mul(c[i], IK))
            combined = combine_value(self.message_bytes, L[i], R[i])
            c[(i + 1) % self.n] = scalar_hash(combined)

        return c[0] == c_value
