import sys


def inv_mod_q(x):
    return pow(x, q - 2, q)


def recover_x(y, sign):
    if y >= q:
        return None

    x2 = (y * y - 1) * inv_mod_q(d * y * y + 1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    x = pow(x2, (q + 3) // 8, q)

    if (x * x - x2) % q != 0:
        x = x * sqrt_mod_q % q

    if (x * x - x2) % q != 0:
        return None

    if (x & 1) != sign:
        x = q - x

    return x


# Base field
q = 2 ** 255 - 19

# Group order
l = 2 ** 252 + 27742317777372353535851937790883648493

# Curve constant
d = -121665 * inv_mod_q(121666) % q

# Square root of -1
sqrt_mod_q = pow(2, (q - 1) // 4, q)

# Base point coordinates
g_y = 4 * inv_mod_q(5) % q
g_x = recover_x(g_y, 0)

# Base point
G = (g_x, g_y, 1, g_x * g_y % q)


def point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % q
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % q
    C = 2 * P[3] * Q[3] * d % q
    D = 2 * P[2] * Q[2] % q
    E = B - A
    F = D - C
    _G = D + C
    H = B + A
    return E * F, _G * H, F * _G, E * H


def point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def point_compress(P):
    z = inv_mod_q(P[2])
    x = P[0] * z % q
    y = P[1] * z % q
    return int.to_bytes(y | ((x & 1) << 255), 32, sys.byteorder)


def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")

    y = int.from_bytes(s, sys.byteorder)
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return x, y, 1, x * y % q
