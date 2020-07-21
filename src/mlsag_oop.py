from src.utils import *


class MLSAG:
    """
    Multilayer Linkable Spontaneous Anonymous Group (MLSAG) signature
    is a ring signature over a set of n key-vectors
    """

    def __init__(self, message, number_of_users, number_of_addresses, PK_vectors):
        """
        :param message: Secret message (bytes)
        :param number_of_users: Number of users
        :param number_of_addresses: Number of one-time addresses
        :param PK_vectors: Public key-vectors
        """
        self.n = number_of_users
        self.m = number_of_addresses
        self.PK_vectors = PK_vectors
        self.message_bytes = str.encode(message)

    @staticmethod
    def image_key(sk, PK):
        H = point_hash(PK)
        I = point_mul(sk, H)
        return I

    @staticmethod
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
                sk_vectors[i][j] = secret_key()
                PK_vectors[i][j] = public_key(sk_vectors[i][j])

        return PK_vectors, sk_vectors[index], index

    def sign(self, sk_vector, index):
        """
        The  ring  signature  algorithm

        :param index: Signer secret index
        :param sk_vector: Secret key-vector

        :return: Image key-vector and auxiliary values in order to be able to check the signature for correctness
        """

        IK_vector = [self.image_key(sk_vector[j], self.PK_vectors[index][j]) for j in range(self.m)]

        L = matrix_gen(self.n, self.m)
        R = matrix_gen(self.n, self.m)
        s = matrix_gen(self.n, self.m)

        a = [field_value_gen() for _ in range(self.m)]
        c = [None for _ in range(self.n)]

        for j in range(self.m):
            H = point_hash(self.PK_vectors[index][j])
            L[index][j] = point_mul(a[j], G)
            R[index][j] = point_mul(a[j], H)

        combined = combine_values(self.message_bytes, L[index], R[index])
        c[(index + 1) % self.n] = scalar_hash(combined)

        for _i in range(index + 1, self.n + index):
            i = _i % self.n
            for j in range(self.m):
                P = self.PK_vectors[i][j]
                H = point_hash(P)
                I = IK_vector[j]
                s[i][j] = field_value_gen()
                L[i][j] = point_add(point_mul(s[i][j], G), point_mul(c[i], P))
                R[i][j] = point_add(point_mul(s[i][j], H), point_mul(c[i], I))
            combined = combine_values(self.message_bytes, L[i], R[i])
            c[(i + 1) % self.n] = scalar_hash(combined)

        combined = combine_values(self.message_bytes, L[index - 1], R[index - 1])
        c[index] = scalar_hash(combined)

        for j in range(self.m):
            s[index][j] = (a[j] - c[index] * sk_vector[j]) % l

        return IK_vector, c[0], s

    def verify(self, IK_vector, c_value, s_vectors):
        """
        The  ring  verification  algorithm

        :param IK_vector: Image key-vector
        :param c_value: Auxiliary value
        :param s_vectors: Auxiliary values

        :return: If the signature is valid or not
        """

        L = matrix_gen(self.n, self.m)
        R = matrix_gen(self.n, self.m)

        c = [None for _ in range(self.n)]
        c[0] = c_value

        for i in range(self.n):
            for j in range(self.m):
                P = self.PK_vectors[i][j]
                H = point_hash(P)
                I = IK_vector[j]
                s = s_vectors[i][j]
                L[i][j] = point_add(point_mul(s, G), point_mul(c[i], P))
                R[i][j] = point_add(point_mul(s, H), point_mul(c[i], I))

            combined = combine_values(self.message_bytes, L[i], R[i])
            c[(i + 1) % self.n] = scalar_hash(combined)

        return c[0] == c_value
