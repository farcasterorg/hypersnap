#!/usr/bin/env python3
"""Pure-Python core-SVP cross-check for the LWE-FSA parameter sets.

This is NOT the authoritative estimate. The authoritative numbers come from
the lattice estimator (https://github.com/malb/lattice-estimator), see
``estimate.py`` in this directory. This script exists so the parameter
choice can be re-checked without Sage, and so the reasoning behind each
number is visible in ~200 lines.

Models (all "core-SVP": the cost of ONE call to an SVP oracle in dimension
beta, ignoring the number of BKZ tours and all polynomial factors):

* classical sieving  2^(0.292 beta)   [BDGL16]
* quantum sieving    2^(0.265 beta)   [Laarhoven thesis; ADPS16 "quantum"]
* BKZ-beta output follows the Geometric Series Assumption with root Hermite
  factor delta(beta) = ((pi beta)^(1/beta) beta / (2 pi e))^(1/(2(beta-1))).

Attacks:

* LWE primal uSVP, "2016 estimate" [ADPS16, AGVW17]: success iff
  sigma * sqrt(beta) <= delta^(2 beta - d - 1) * q^(m'/d), d = n_s + m' + 1,
  minimised over the number of samples m' used.
* LWE dual distinguishing [Kyber/Dilithium security scripts]: a BKZ-beta dual
  vector of length l = delta^d q^(n_s/d) gives advantage
  eps = exp(-2 pi^2 (l sigma / q)^2); one sieve yields 2^(0.2075 beta) such
  vectors, so the attack repeats max(1, 1/(eps^2 2^(0.2075 beta))) times.
* SIS in the infinity norm [Dilithium round-3 spec, Section 6.2 /
  MSIS_security.py]: BKZ-beta on a randomized q-ary basis; the sieve
  vectors of length l = exp(L[0]) have Gaussian coordinates of standard
  deviation l/sqrt(d) in the reduced block and uniform coordinates mod q in
  the head; the attack repeats until one vector falls in [-zeta, zeta]^w.

Usage:  python3 coresvp.py            # provisional set + Dilithium calibration
"""

from math import ceil, erf, exp, floor, log, log2, pi, sqrt

C_CLASSICAL = log2(sqrt(3.0 / 2.0))  # 0.2925
C_QUANTUM = log2(sqrt(13.0 / 9.0))  # 0.2653
C_NVEC = log2(sqrt(4.0 / 3.0))  # 0.2075 (vectors output by one sieve)


def delta_bkz(b):
    return ((pi * b) ** (1.0 / b) * b / (2 * pi * exp(1))) ** (1.0 / (2.0 * b - 2.0))


# --------------------------------------------------------------------------
# LWE
# --------------------------------------------------------------------------


def lwe_primal_beta(n_s, m_max, q, sigma):
    """Smallest beta for which the primal uSVP attack succeeds."""
    lq = log(q)
    for b in range(50, 3 * (n_s + m_max)):
        ld = log(delta_bkz(b))
        lhs = log(sigma) + 0.5 * log(b)
        for mp in range(max(0, b - n_s), m_max + 1, 4):
            d = n_s + mp + 1
            if b > d:
                continue
            rhs = (2 * b - d - 1) * ld + (mp / d) * lq
            if lhs <= rhs:
                return b, mp
    return None, None


def lwe_dual_cost(n_s, m_max, q, sigma, c_svp):
    """Cheapest dual attack: returns (log2 cost, beta, m')."""
    best = (float("inf"), None, None)
    for b in range(50, 2 * (n_s + m_max)):
        if c_svp * b > best[0]:
            break
        ld = log(delta_bkz(b))
        for mp in range(max(1, b - n_s), m_max + 1, 8):
            d = n_s + mp
            ll = d * ld + (n_s / d) * log(q)  # log of dual vector length
            tau = exp(ll) * sigma / q
            log2_eps = -2 * pi * pi * tau * tau / log(2)
            log2_r = max(0.0, -2 * log2_eps - C_NVEC * b)
            cost = c_svp * b + log2_r
            if cost < best[0]:
                best = (cost, b, mp)
    return best


# --------------------------------------------------------------------------
# SIS, infinity norm
# --------------------------------------------------------------------------


def bkz_shape_randomized(q, nq, n1, b):
    """GSA log-profile of a randomized q-ary basis after BKZ-b."""
    glv = nq * log(q)
    d = nq + n1
    slope = -2 * log(delta_bkz(b))
    L = []
    li = 0.0
    lv = 0.0
    for _ in range(d):
        li -= slope
        lv += li
        if lv > glv:
            break
        L = [li] + L
    nb = len(L)
    L += (d - nb) * [0.0]
    diff = sum(L) - glv
    for i in range(nb):
        L[i] -= diff / nb
    return 0, nb, L


def sis_linf_cost(q, w, h, zeta, b, c_svp):
    i, j, L = bkz_shape_randomized(q, h, w - h, b)
    l = exp(L[i])
    d = j - i
    sigma = l / sqrt(d)
    p_middle = erf(zeta / (sigma * sqrt(2.0)))
    p_head = min(1.0, 2.0 * zeta / q)
    if p_middle <= 0:
        return float("inf")
    log2_eps = d * log2(p_middle) + i * log2(p_head)
    log2_r = max(0.0, -log2_eps - C_NVEC * b)
    return c_svp * b + log2_r


def sis_linf(q, w, h, zeta, c_svp):
    """Cheapest infinity-norm SIS attack: returns (log2 cost, beta)."""
    best = (float("inf"), None)
    for b in range(50, w):
        if c_svp * b > best[0]:
            break
        cost = sis_linf_cost(q, w, h, zeta, b, c_svp)
        if cost < best[0]:
            best = (cost, b)
    return best


# --------------------------------------------------------------------------
# Parameter sets (keep in sync with src/params.rs)
# --------------------------------------------------------------------------

PROVISIONAL_V1 = dict(
    name="LWE-FSA provisional v1 (id 1)",
    q=4193633,  # 2^22 - 671, prime, q - 1 = 32 * 131051
    n=1280,
    m=1280,
    k=256,
    kappa=60,
    eta=1,
    gamma1=2**18,
    gamma2=131051,  # (q - 1) / 32
)


def report(p):
    q, n, m, k = p["q"], p["n"], p["m"], p["k"]
    kappa, eta, g1, g2 = p["kappa"], p["eta"], p["gamma1"], p["gamma2"]
    beta_sc = kappa * eta
    bz = g1 - beta_sc - 1
    sigma = sqrt(eta * (eta + 1) / 3.0)  # uniform on [-eta, eta]
    print("== %s ==" % p["name"])
    print("q=%d (2^%.2f) n=%d m=%d k=%d kappa=%d eta=%d gamma1=%d gamma2=%d B=%d"
          % (q, log2(q), n, m, k, kappa, eta, g1, g2, bz))

    # LWE key recovery: secret dimension m, n samples, sigma for S and E.
    b_p, m_p = lwe_primal_beta(m, n, q, sigma)
    print("LWE primal uSVP : beta=%d (samples used %d)  classical %.1f  quantum %.1f"
          % (b_p, m_p, C_CLASSICAL * b_p, C_QUANTUM * b_p))
    for label, c in (("classical", C_CLASSICAL), ("quantum", C_QUANTUM)):
        cost, b_d, m_d = lwe_dual_cost(m, n, q, sigma, c)
        print("LWE dual        : beta=%d (samples used %d)  %s %.1f" % (b_d, m_d, label, cost))

    # SIS forgery: [A | T | I_n], n rows, m + k + n columns.
    w = m + k + n
    for label, zeta in (("weak unforgeability  ", max(bz, 2 * g2 + 1)),
                        ("strong unforgeability", max(2 * bz, 4 * g2 + 2))):
        cc, b_c = sis_linf(q, w, n, zeta, C_CLASSICAL)
        cq, b_q = sis_linf(q, w, n, zeta, C_QUANTUM)
        print("SIS %s: zeta=%d  beta=%d  classical %.1f  quantum %.1f"
              % (label, zeta, b_c, cc, cq))
    print()


def calibrate():
    """Reproduce published Dilithium round-3 core-SVP block sizes."""
    print("== calibration: Dilithium round 3 (published: LWE 423/623, SIS 423/638) ==")
    for name, (kk, ll, eta, zeta) in {
        "Dilithium2": (4, 4, 2, 350209),
        "Dilithium3": (6, 5, 4, 724481),
    }.items():
        sigma = sqrt(eta * (eta + 1) / 3.0)
        b_p, _ = lwe_primal_beta(256 * ll, 256 * kk, 8380417, sigma)
        _, b_s = sis_linf(8380417, 256 * (kk + ll + 1), 256 * kk, zeta, C_CLASSICAL)
        print("%s: LWE primal beta=%d  SIS(weak) beta=%d" % (name, b_p, b_s))
    print()


if __name__ == "__main__":
    calibrate()
    report(PROVISIONAL_V1)
