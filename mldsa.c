/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include <stdint.h>
#include <string.h>

#include "shake.h"
#include "random.h"
#include "utils.h"
#include "mldsa.h"

#define MLD_DEFAULT_ALIGN 32
#define MLD_ALIGN_UP(N) \
  ((((N) + (MLD_DEFAULT_ALIGN - 1)) / MLD_DEFAULT_ALIGN) * MLD_DEFAULT_ALIGN)
#if defined(__GNUC__)
#define MLD_ALIGN __attribute__((aligned(MLD_DEFAULT_ALIGN)))
#elif defined(_MSC_VER)
#define MLD_ALIGN __declspec(align(MLD_DEFAULT_ALIGN))
#else
#define MLD_ALIGN /* No known support for alignment constraints */
#endif

#define MLDSA_SEEDBYTES 32
#define MLDSA_CRHBYTES 64
#define MLDSA_TRBYTES 64
#define MLDSA_RNDBYTES 32
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_Q_HALF ((MLDSA_Q + 1) / 2) /* 4190209 */
#define MLDSA_D 13

#define MLDSA_K 4
#define MLDSA_L 4
#define MLDSA_ETA 2
#define MLDSA_TAU 39
#define MLDSA_BETA 78
#define MLDSA_GAMMA1 (1 << 17)
#define MLDSA_GAMMA2 ((MLDSA_Q - 1) / 88)
#define MLDSA_OMEGA 80
#define MLDSA_CTILDEBYTES 32
#define MLDSA_POLYZ_PACKEDBYTES 576
#define MLDSA_POLYW1_PACKEDBYTES 192
#define MLDSA_POLYETA_PACKEDBYTES 96

#define MLDSA_POLYT1_PACKEDBYTES 320
#define MLDSA_POLYT0_PACKEDBYTES 416
#define MLDSA_POLYVECH_PACKEDBYTES (MLDSA_OMEGA + MLDSA_K)

#define CRYPTO_PUBLICKEYBYTES \
  (MLDSA_SEEDBYTES + MLDSA_K * MLDSA_POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES                                                  \
  (2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + MLDSA_L * MLDSA_POLYETA_PACKEDBYTES + \
   MLDSA_K * MLDSA_POLYETA_PACKEDBYTES + MLDSA_K * MLDSA_POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES                                       \
  (MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES + \
   MLDSA_POLYVECH_PACKEDBYTES)

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define mld_xof256_ctx keccak_state
#define mld_xof256_init(CTX) shake256_init(CTX)
#define mld_xof256_absorb(CTX, IN, INBYTES) \
  do                                        \
  {                                         \
    shake256_absorb(CTX, IN, INBYTES);      \
    shake256_finalize(CTX);                 \
  } while (0)
#define mld_xof256_release(CTX) shake256_release(CTX)

#define mld_xof256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

#define mld_xof128_ctx keccak_state
#define mld_xof128_init(CTX) shake128_init(CTX)
#define mld_xof128_absorb(CTX, IN, INBYTES) \
  do                                        \
  {                                         \
    shake128_absorb(CTX, IN, INBYTES);      \
    shake128_finalize(CTX);                 \
  } while (0)
#define mld_xof128_release(CTX) shake128_release(CTX)


#define mld_xof128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)

#define mld_xof256_x4_ctx mld_shake256x4ctx
#define mld_xof256_x4_init(CTX) mld_shake256x4_init((CTX))
#define mld_xof256_x4_absorb(CTX, IN, INBYTES)                          \
  mld_shake256x4_absorb_once((CTX), (IN)[0], (IN)[1], (IN)[2], (IN)[3], \
                             (INBYTES))
#define mld_xof256_x4_squeezeblocks(BUF, NBLOCKS, CTX)                 \
  mld_shake256x4_squeezeblocks((BUF)[0], (BUF)[1], (BUF)[2], (BUF)[3], \
                               (NBLOCKS), (CTX))
#define mld_xof256_x4_release(CTX) mld_shake256x4_release((CTX))

#define mld_xof128_x4_ctx mld_shake128x4ctx
#define mld_xof128_x4_init(CTX) mld_shake128x4_init((CTX))
#define mld_xof128_x4_absorb(CTX, IN, INBYTES)                          \
  mld_shake128x4_absorb_once((CTX), (IN)[0], (IN)[1], (IN)[2], (IN)[3], \
                             (INBYTES))
#define mld_xof128_x4_squeezeblocks(BUF, NBLOCKS, CTX)                 \
  mld_shake128x4_squeezeblocks((BUF)[0], (BUF)[1], (BUF)[2], (BUF)[3], \
                               (NBLOCKS), (CTX))
#define mld_xof128_x4_release(CTX) mld_shake128x4_release((CTX))

static int32_t mld_cast_uint32_to_int32(uint32_t x)
{
  /*
   * PORTABILITY: This relies on uint32_t -> int32_t
   * being implemented as the inverse of int32_t -> uint32_t,
   * which is implementation-defined (C99 6.3.1.3 (3))
   * CBMC (correctly) fails to prove this conversion is OK,
   * so we have to suppress that check here
   */
  return (int32_t)x;
}

static int32_t montgomery_reduce(int64_t a)
{
  /* check-magic: 58728449 == unsigned_mod(pow(MLDSA_Q, -1, 2^32), 2^32) */
  const uint64_t QINV = 58728449;

  /*  Compute a*q^{-1} mod 2^32 in unsigned representatives */
  const uint32_t a_reduced = a & UINT32_MAX;
  const uint32_t a_inverted = (a_reduced * QINV) & UINT32_MAX;

  /* Lift to signed canonical representative mod 2^16. */
  const int32_t t = mld_cast_uint32_to_int32(a_inverted);

  int64_t r;

  r = a - ((int64_t)t * MLDSA_Q);

  /*
   * PORTABILITY: Right-shift on a signed integer is, strictly-speaking,
   * implementation-defined for negative left argument. Here,
   * we assume it's sign-preserving "arithmetic" shift right. (C99 6.5.7 (5))
   */
  r = r >> 32;
  return (int32_t)r;
}

static int32_t reduce32(int32_t a)
{
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t * MLDSA_Q;
  return t;
}

static int32_t caddq(int32_t a)
{
  a += (a >> 31) & MLDSA_Q;
  return a;
}

static void power2round(int32_t *a0, int32_t *a1, const int32_t a)
{
  *a1 = (a + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
  *a0 = a - (*a1 << MLDSA_D);
}

static void decompose(int32_t *a0, int32_t *a1, int32_t a)
{
  *a1 = (a + 127) >> 7;
  /* We know a >= 0 and a < MLDSA_Q, so... */
  *a1 = (*a1 * 11275 + (1 << 23)) >> 24;
  *a1 ^= ((43 - *a1) >> 31) & *a1;
  *a0 = a - *a1 * 2 * MLDSA_GAMMA2;
  *a0 -= (((MLDSA_Q - 1) / 2 - *a0) >> 31) & MLDSA_Q;
}

static unsigned int make_hint(int32_t a0, int32_t a1)
{
  if (a0 > MLDSA_GAMMA2 || a0 < -MLDSA_GAMMA2 ||
      (a0 == -MLDSA_GAMMA2 && a1 != 0))
  {
    return 1;
  }

  return 0;
}

static int32_t use_hint(int32_t a, unsigned int hint)
{
  int32_t a0, a1;

  decompose(&a0, &a1, a);
  if (hint == 0)
  {
    return a1;
  }

  if (a0 > 0)
  {
    return (a1 == 43) ? 0 : a1 + 1;
  }
  else
  {
    return (a1 == 0) ? 43 : a1 - 1;
  }
}

/*
 * Table of zeta values used in the reference NTT and inverse NTT.
 * See autogen for details.
 */
static const int32_t zetas[MLDSA_N] = {
    0,        25847,    -2608894, -518909,  237124,   -777960,  -876248,
    466468,   1826347,  2353451,  -359251,  -2091905, 3119733,  -2884855,
    3111497,  2680103,  2725464,  1024112,  -1079900, 3585928,  -549488,
    -1119584, 2619752,  -2108549, -2118186, -3859737, -1399561, -3277672,
    1757237,  -19422,   4010497,  280005,   2706023,  95776,    3077325,
    3530437,  -1661693, -3592148, -2537516, 3915439,  -3861115, -3043716,
    3574422,  -2867647, 3539968,  -300467,  2348700,  -539299,  -1699267,
    -1643818, 3505694,  -3821735, 3507263,  -2140649, -1600420, 3699596,
    811944,   531354,   954230,   3881043,  3900724,  -2556880, 2071892,
    -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455,  -1585221, -1257611, 1939314,  -4083598, -1000202, -3190144,
    -3157330, -3632928, 126922,   3412210,  -983419,  2147896,  2715295,
    -2967645, -3693493, -411027,  -2477047, -671102,  -1228525, -22981,
    -1308169, -381987,  1349076,  1852771,  -1430430, -3343383, 264944,
    508951,   3097992,  44288,    -1100098, 904516,   3958618,  -3724342,
    -8578,    1653064,  -3249728, 2389356,  -210977,  759969,   -1316856,
    189548,   -3553272, 3159746,  -1851402, -2409325, -177440,  1315589,
    1341330,  1285669,  -1584928, -812732,  -1439742, -3019102, -3881060,
    -3628969, 3839961,  2091667,  3407706,  2316500,  3817976,  -3342478,
    2244091,  -2446433, -3562462, 266997,   2434439,  -1235728, 3513181,
    -3520352, -3759364, -1197226, -3193378, 900702,   1859098,  909542,
    819034,   495491,   -1613174, -43260,   -522500,  -655327,  -3122442,
    2031748,  3207046,  -3556995, -525098,  -768622,  -3595838, 342297,
    286988,   -2437823, 4108315,  3437287,  -3342277, 1735879,  203044,
    2842341,  2691481,  -2590150, 1265009,  4055324,  1247620,  2486353,
    1595974,  -3767016, 1250494,  2635921,  -3548272, -2994039, 1869119,
    1903435,  -1050970, -1333058, 1237275,  -3318210, -1430225, -451100,
    1312455,  3306115,  -1962642, -1279661, 1917081,  -2546312, -1374803,
    1500165,  777191,   2235880,  3406031,  -542412,  -2831860, -1671176,
    -1846953, -2584293, -3724270, 594136,   -3776993, -2013608, 2432395,
    2454455,  -164721,  1957272,  3369112,  185531,   -1207385, -3183426,
    162844,   1616392,  3014001,  810149,   1652634,  -3694233, -1799107,
    -3038916, 3523897,  3866901,  269760,   2213111,  -975884,  1717735,
    472078,   -426683,  1723600,  -1803090, 1910376,  -1667432, -1104333,
    -260646,  -3833893, -2939036, -2235985, -420899,  -2286327, 183443,
    -976891,  1612842,  -3545687, -554416,  3919660,  -48306,   -1362209,
    3937738,  1400424,  -846154,  1976782,
};

static int32_t mld_fqmul(int32_t a, int32_t b)
{
  return montgomery_reduce((int64_t)a * (int64_t)b);
  /* TODO: reason about bounds */
}

/*************************************************
 * Name:        mld_fqsacle
 *
 * Description: Scales a field element by mont/256 , i.e., performs Montgomery
 *              multiplication by mont^2/256.
 *              Input is expected to have absolute value smaller than
 *              256 * MLDSA_Q.
 *              Output has absolute value smaller than MLD_INTT_BOUND (4211139).
 *
 * Arguments:   - int32_t a: Field element to be scaled.
 **************************************************/
static int32_t mld_fqscale(int32_t a)
{
  const int32_t f = 41978; /* mont^2/256 */
  return montgomery_reduce((int64_t)a * f);
  /* TODO: reason about bounds */
}


/* mld_ntt_butterfly_block()
 *
 * Computes a block CT butterflies with a fixed twiddle factor,
 * using Montgomery multiplication.
 *
 * Parameters:
 * - r: Pointer to base of polynomial (_not_ the base of butterfly block)
 * - zeta: Twiddle factor to use for the butterfly. This must be in
 *         Montgomery form and signed canonical.
 * - start: Offset to the beginning of the butterfly block
 * - len: Index difference between coefficients subject to a butterfly
 * - bound: Ghost variable describing coefficient bound: Prior to `start`,
 *          coefficients must be bound by `bound + MLDSA_Q`. Post `start`,
 *          they must be bound by `bound`.
 * When this function returns, output coefficients in the index range
 * [start, start+2*len) have bound bumped to `bound + MLDSA_Q`.
 * Example:
 * - start=8, len=4
 *   This would compute the following four butterflies
 *          8     --    12
 *             9    --     13
 *                10   --     14
 *                   11   --     15
 * - start=4, len=2
 *   This would compute the following two butterflies
 *          4 -- 6
 *             5 -- 7
 */

/* Reference: Embedded in `ntt()` in the reference implementation. */
static void mld_ntt_butterfly_block(int32_t r[MLDSA_N], const int32_t zeta,
                                    const unsigned start, const unsigned len,
                                    const int32_t bound)
{
  /* `bound` is a ghost variable only needed in the CBMC specification */
  unsigned j;
  ((void)bound);
  for (j = start; j < start + len; j++)
  {
    int32_t t;
    t = mld_fqmul(r[j + len], zeta);
    r[j + len] = r[j] - t;
    r[j] = r[j] + t;
  }
}

/* mld_ntt_layer()
 *
 * Compute one layer of forward NTT
 *
 * Parameters:
 * - r:     Pointer to base of polynomial
 * - layer: Indicates which layer is being applied.
 */

/* Reference: Embedded in `ntt()` in the reference implementation. */
static void mld_ntt_layer(int32_t r[MLDSA_N], const unsigned layer)
{
  unsigned start, k, len;
  /* Twiddle factors for layer n are at indices 2^(n-1)..2^n-1. */
  k = 1u << (layer - 1);
  len = MLDSA_N >> layer;
  for (start = 0; start < MLDSA_N; start += 2 * len)
  {
    int32_t zeta = zetas[k++];
    mld_ntt_butterfly_block(r, zeta, start, len, layer * MLDSA_Q);
  }
}


static void ntt(int32_t a[MLDSA_N])
{
  unsigned int layer;

  for (layer = 1; layer < 9; layer++)
  {
    mld_ntt_layer(a, layer);
  }

  /* When the loop exits, layer == 9, so the loop invariant  */
  /* directly implies the postcondition in that coefficients */
  /* are bounded in magnitude by 9 * MLDSA_Q                 */
}

/* Reference: Embedded into `invntt_tomont()` in the reference implementation
 * [@REF] */
static void mld_invntt_layer(int32_t r[MLDSA_N], unsigned layer)
{
  unsigned start, k, len;
  len = (MLDSA_N >> layer);
  k = (1u << layer) - 1;
  for (start = 0; start < MLDSA_N; start += 2 * len)
  {
    unsigned j;
    int32_t zeta = -zetas[k--];

    for (j = start; j < start + len; j++)
    {
      int32_t t = r[j];
      r[j] = t + r[j + len];
      r[j + len] = t - r[j + len];
      r[j + len] = mld_fqmul(r[j + len], zeta);
    }
  }
}

/*************************************************
 * Name:        invntt_tomont
 *
 * Description: Inverse NTT and multiplication by Montgomery factor mont^2 /256.
 *              In-place. No modular reductions after additions or subtractions;
 *              Input coefficients need to be smaller than MLDSA_Q
 *              in absolute value.
 *              Output coefficient are smaller than MLD_INTT_BOUND
 *              in absolute value.
 *
 * Arguments:   - int32_t a[MLDSA_N]: input/output coefficient array
 **************************************************/
static void invntt_tomont(int32_t a[MLDSA_N])

{
  unsigned int layer, j;

  for (layer = 8; layer >= 1; layer--)
  {
    mld_invntt_layer(a, layer);
  }

  /* Coefficient bounds are now at 256Q. We now scale by mont / 256,
   * i.e., compute the Montgomery multiplication by mont^2 / 256.
   * mont corrects the mont^-1  factor introduced in the basemul.
   * 1/256 performs that scaling of the inverse NTT.
   * The reduced value is bounded by  MLD_INTT_BOUND (4211139) in absolute
   * value.*/
  for (j = 0; j < MLDSA_N; ++j)
  {
    a[j] = mld_fqscale(a[j]);
  }
}

typedef struct
{
  int32_t coeffs[MLDSA_N];
} MLD_ALIGN poly;

typedef struct
{
  poly vec[MLDSA_L];
} polyvecl;

typedef struct
{
  poly vec[MLDSA_K];
} polyveck;

static void poly_reduce(poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    a->coeffs[i] = reduce32(a->coeffs[i]);
  }
}

static void poly_caddq(poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    a->coeffs[i] = caddq(a->coeffs[i]);
  }
}
/* Reference: We use destructive version (output=first input) to avoid
 *            reasoning about aliasing in the CBMC specification */
static void poly_add(poly *r, const poly *b)
{
  unsigned int i;
  for (i = 0; i < MLDSA_N; ++i)
  {
    r->coeffs[i] = r->coeffs[i] + b->coeffs[i];
  }
}

/* Reference: We use destructive version (output=first input) to avoid
 *            reasoning about aliasing in the CBMC specification */
static void poly_sub(poly *r, const poly *b)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    r->coeffs[i] = r->coeffs[i] - b->coeffs[i];
  }
}

static void poly_shiftl(poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; i++)
  {
    /* Reference: uses a left shift by MLDSA_D which is undefined behaviour in
     * C90/C99
     */
    a->coeffs[i] *= (1 << MLDSA_D);
  }
}

static void poly_ntt(poly *a)
{
  ntt(a->coeffs);
}

static void poly_invntt_tomont(poly *a)
{
  invntt_tomont(a->coeffs);
}

static void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
  }
}

static void poly_power2round(poly *a1, poly *a0, const poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    power2round(&a0->coeffs[i], &a1->coeffs[i], a->coeffs[i]);
  }
}

static void poly_decompose(poly *a1, poly *a0, const poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    decompose(&a0->coeffs[i], &a1->coeffs[i], a->coeffs[i]);
  }
}

static unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1)
{
  unsigned int i, s = 0;

  for (i = 0; i < MLDSA_N; ++i)
  {
    const unsigned int hint_bit = make_hint(a0->coeffs[i], a1->coeffs[i]);
    h->coeffs[i] = hint_bit;
    s += hint_bit;
  }

  return s;
}

static void poly_use_hint(poly *b, const poly *a, const poly *h)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N; ++i)
  {
    b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
  }
}

/* Reference: explicitly checks the bound B to be <= (MLDSA_Q - 1) / 8).
 * This is unnecessary as it's always a compile-time constant.
 * We instead model it as a precondition.
 */
static int poly_chknorm(const poly *a, int32_t B)
{
  unsigned int i;
  int rc = 0;
  int32_t t;

  /* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */

  for (i = 0; i < MLDSA_N; ++i)
  {
    /* Absolute value */
    t = a->coeffs[i] >> 31;
    t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

    if (t >= B)
    {
      rc = 1;
    }
  }

  return rc;
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Sample uniformly random coefficients in [0, MLDSA_Q-1] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - int32_t *a: pointer to output array (allocated)
 *              - unsigned int target:  requested number of coefficients to
 *sample
 *              - unsigned int offset:  number of coefficients already sampled
 *              - const uint8_t *buf: array of random bytes to sample from
 *              - unsigned int buflen: length of array of random bytes (must be
 *                multiple of 3)
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/

/* Reference: `rej_uniform()` in the reference implementation [@REF].
 *            - Our signature differs from the reference implementation
 *              in that it adds the offset and always expects the base of the
 *              target buffer. This avoids shifting the buffer base in the
 *              caller, which appears tricky to reason about. */
#define POLY_UNIFORM_NBLOCKS \
  ((768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES)
static unsigned int rej_uniform(int32_t *a, unsigned int target,
                                unsigned int offset, const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;

  ctr = offset;
  pos = 0;
  /* pos + 3 cannot overflow due to the assumption
  buflen <= (POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES) */
  while (ctr < target && pos + 3 <= buflen)
  {
    t = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if (t < MLDSA_Q)
    {
      a[ctr++] = t;
    }
  }

  return ctr;
}

/* Reference: poly_uniform() in the reference implementation [@REF].
 *           - Simplified from reference by removing buffer tail handling
 *             since buflen % 3 = 0 always holds true (STREAM128_BLOCKBYTES =
 *             168).
 *           - Modified rej_uniform interface to track offset directly.
 *           - Pass nonce packed in the extended seed array instead of a third
 *             argument.
 * */
static void poly_uniform(poly *a, const uint8_t seed[MLDSA_SEEDBYTES + 2])
{
  unsigned int ctr;
  unsigned int buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
  MLD_ALIGN uint8_t buf[POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES];
  mld_xof128_ctx state;

  mld_xof128_init(&state);
  mld_xof128_absorb(&state, seed, MLDSA_SEEDBYTES + 2);
  mld_xof128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

  ctr = rej_uniform(a->coeffs, MLDSA_N, 0, buf, buflen);
  buflen = STREAM128_BLOCKBYTES;
  while (ctr < MLDSA_N)
  {
    mld_xof128_squeezeblocks(buf, 1, &state);
    ctr = rej_uniform(a->coeffs, MLDSA_N, ctr, buf, buflen);
  }
  mld_xof128_release(&state);
}

static void
poly_uniform_4x(poly *vec0, poly *vec1, poly *vec2, poly *vec3,
                uint8_t seed[4][MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)])
{
  /* Temporary buffers for XOF output before rejection sampling */
  MLD_ALIGN uint8_t
      buf[4][MLD_ALIGN_UP(POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES)];

  /* Tracks the number of coefficients we have already sampled */
  unsigned ctr[4];
  mld_xof128_x4_ctx state;
  unsigned buflen;

  mld_xof128_x4_init(&state);
  mld_xof128_x4_absorb(&state, seed, MLDSA_SEEDBYTES + 2);

  /*
   * Initially, squeeze heuristic number of POLY_UNIFORM_NBLOCKS.
   * This should generate the matrix entries with high probability.
   */

  mld_xof128_x4_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);
  buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
  ctr[0] = rej_uniform(vec0->coeffs, MLDSA_N, 0, buf[0], buflen);
  ctr[1] = rej_uniform(vec1->coeffs, MLDSA_N, 0, buf[1], buflen);
  ctr[2] = rej_uniform(vec2->coeffs, MLDSA_N, 0, buf[2], buflen);
  ctr[3] = rej_uniform(vec3->coeffs, MLDSA_N, 0, buf[3], buflen);

  /*
   * So long as not all matrix entries have been generated, squeeze
   * one more block a time until we're done.
   */
  buflen = STREAM128_BLOCKBYTES;
  while (ctr[0] < MLDSA_N || ctr[1] < MLDSA_N || ctr[2] < MLDSA_N ||
         ctr[3] < MLDSA_N)
  {
    mld_xof128_x4_squeezeblocks(buf, 1, &state);
    ctr[0] = rej_uniform(vec0->coeffs, MLDSA_N, ctr[0], buf[0], buflen);
    ctr[1] = rej_uniform(vec1->coeffs, MLDSA_N, ctr[1], buf[1], buflen);
    ctr[2] = rej_uniform(vec2->coeffs, MLDSA_N, ctr[2], buf[2], buflen);
    ctr[3] = rej_uniform(vec3->coeffs, MLDSA_N, ctr[3], buf[3], buflen);
  }
  mld_xof128_x4_release(&state);
}

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-MLDSA_ETA, MLDSA_ETA]
 *by performing rejection sampling on array of random bytes.
 *
 * Arguments:   - int32_t *a:          pointer to output array (allocated)
 *              - unsigned int target: requested number of coefficients to
 *sample
 *              - unsigned int offset: number of coefficients already sampled
 *              - const uint8_t *buf:  array of random bytes to sample from
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than target if not
 *enough random bytes were given.
 **************************************************/

/* Reference: `rej_eta()` in the reference implementation [@REF].
 *            - Our signature differs from the reference implementation
 *              in that it adds the offset and always expects the base of the
 *              target buffer. This avoids shifting the buffer base in the
 *              caller, which appears tricky to reason about. */
#define POLY_UNIFORM_ETA_NBLOCKS \
  ((136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)
static unsigned int rej_eta(int32_t *a, unsigned int target,
                            unsigned int offset, const uint8_t *buf,
                            unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;

  ctr = offset;
  pos = 0;
  while (ctr < target && pos < buflen)
  {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

    if (t0 < 15)
    {
      t0 = t0 - (205 * t0 >> 10) * 5;
      a[ctr++] = 2 - (int32_t)t0;
    }
    if (t1 < 15 && ctr < target)
    {
      t1 = t1 - (205 * t1 >> 10) * 5;
      a[ctr++] = 2 - (int32_t)t1;
    }
  }

  return ctr;
}

static void
poly_uniform_eta_4x(poly *r0, poly *r1, poly *r2, poly *r3,
                    const uint8_t seed[MLDSA_CRHBYTES], uint8_t nonce0,
                    uint8_t nonce1, uint8_t nonce2, uint8_t nonce3)
{
  /* Temporary buffers for XOF output before rejection sampling */
  MLD_ALIGN uint8_t
      buf[4][MLD_ALIGN_UP(POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES)];

  MLD_ALIGN uint8_t extseed[4][MLD_ALIGN_UP(MLDSA_CRHBYTES + 2)];

  /* Tracks the number of coefficients we have already sampled */
  unsigned ctr[4];
  mld_xof256_x4_ctx state;
  unsigned buflen;

  memcpy(extseed[0], seed, MLDSA_CRHBYTES);
  memcpy(extseed[1], seed, MLDSA_CRHBYTES);
  memcpy(extseed[2], seed, MLDSA_CRHBYTES);
  memcpy(extseed[3], seed, MLDSA_CRHBYTES);
  extseed[0][MLDSA_CRHBYTES] = nonce0;
  extseed[1][MLDSA_CRHBYTES] = nonce1;
  extseed[2][MLDSA_CRHBYTES] = nonce2;
  extseed[3][MLDSA_CRHBYTES] = nonce3;
  extseed[0][MLDSA_CRHBYTES + 1] = 0;
  extseed[1][MLDSA_CRHBYTES + 1] = 0;
  extseed[2][MLDSA_CRHBYTES + 1] = 0;
  extseed[3][MLDSA_CRHBYTES + 1] = 0;

  mld_xof256_x4_init(&state);
  mld_xof256_x4_absorb(&state, extseed, MLDSA_CRHBYTES + 2);

  /*
   * Initially, squeeze heuristic number of POLY_UNIFORM_ETA_NBLOCKS.
   * This should generate the coefficients with high probability.
   */
  mld_xof256_x4_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);
  buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES;

  ctr[0] = rej_eta(r0->coeffs, MLDSA_N, 0, buf[0], buflen);
  ctr[1] = rej_eta(r1->coeffs, MLDSA_N, 0, buf[1], buflen);
  ctr[2] = rej_eta(r2->coeffs, MLDSA_N, 0, buf[2], buflen);
  ctr[3] = rej_eta(r3->coeffs, MLDSA_N, 0, buf[3], buflen);

  /*
   * So long as not all entries have been generated, squeeze
   * one more block a time until we're done.
   */
  buflen = STREAM256_BLOCKBYTES;
  while (ctr[0] < MLDSA_N || ctr[1] < MLDSA_N || ctr[2] < MLDSA_N ||
         ctr[3] < MLDSA_N)
  {
    mld_xof256_x4_squeezeblocks(buf, 1, &state);
    ctr[0] = rej_eta(r0->coeffs, MLDSA_N, ctr[0], buf[0], buflen);
    ctr[1] = rej_eta(r1->coeffs, MLDSA_N, ctr[1], buf[1], buflen);
    ctr[2] = rej_eta(r2->coeffs, MLDSA_N, ctr[2], buf[2], buflen);
    ctr[3] = rej_eta(r3->coeffs, MLDSA_N, ctr[3], buf[3], buflen);
  }

  mld_xof256_x4_release(&state);
}

static void polyz_unpack(poly *r, const uint8_t *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N / 4; ++i)
  {
    r->coeffs[4 * i + 0] = a[9 * i + 0];
    r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 1] << 8;
    r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 2] << 16;
    r->coeffs[4 * i + 0] &= 0x3FFFF;

    r->coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
    r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 3] << 6;
    r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 4] << 14;
    r->coeffs[4 * i + 1] &= 0x3FFFF;

    r->coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
    r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 5] << 4;
    r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 6] << 12;
    r->coeffs[4 * i + 2] &= 0x3FFFF;

    r->coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
    r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 7] << 2;
    r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 8] << 10;
    r->coeffs[4 * i + 3] &= 0x3FFFF;

    r->coeffs[4 * i + 0] = MLDSA_GAMMA1 - r->coeffs[4 * i + 0];
    r->coeffs[4 * i + 1] = MLDSA_GAMMA1 - r->coeffs[4 * i + 1];
    r->coeffs[4 * i + 2] = MLDSA_GAMMA1 - r->coeffs[4 * i + 2];
    r->coeffs[4 * i + 3] = MLDSA_GAMMA1 - r->coeffs[4 * i + 3];
  }
}


#define POLY_UNIFORM_GAMMA1_NBLOCKS \
  ((MLDSA_POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES)

static void
poly_uniform_gamma1_4x(poly *r0, poly *r1, poly *r2, poly *r3,
                       const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce0,
                       uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{
  /* Temporary buffers for XOF output before rejection sampling */
  MLD_ALIGN uint8_t
      buf[4][MLD_ALIGN_UP(POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES)];

  MLD_ALIGN uint8_t extseed[4][MLD_ALIGN_UP(MLDSA_CRHBYTES + 2)];

  /* Tracks the number of coefficients we have already sampled */
  mld_xof256_x4_ctx state;

  memcpy(extseed[0], seed, MLDSA_CRHBYTES);
  memcpy(extseed[1], seed, MLDSA_CRHBYTES);
  memcpy(extseed[2], seed, MLDSA_CRHBYTES);
  memcpy(extseed[3], seed, MLDSA_CRHBYTES);
  extseed[0][MLDSA_CRHBYTES] = nonce0 & 0xFF;
  extseed[1][MLDSA_CRHBYTES] = nonce1 & 0xFF;
  extseed[2][MLDSA_CRHBYTES] = nonce2 & 0xFF;
  extseed[3][MLDSA_CRHBYTES] = nonce3 & 0xFF;
  extseed[0][MLDSA_CRHBYTES + 1] = nonce0 >> 8;
  extseed[1][MLDSA_CRHBYTES + 1] = nonce1 >> 8;
  extseed[2][MLDSA_CRHBYTES + 1] = nonce2 >> 8;
  extseed[3][MLDSA_CRHBYTES + 1] = nonce3 >> 8;

  mld_xof256_x4_init(&state);
  mld_xof256_x4_absorb(&state, extseed, MLDSA_CRHBYTES + 2);
  mld_xof256_x4_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);

  polyz_unpack(r0, buf[0]);
  polyz_unpack(r1, buf[1]);
  polyz_unpack(r2, buf[2]);
  polyz_unpack(r3, buf[3]);
  mld_xof256_x4_release(&state);
}


static void poly_challenge(poly *c, const uint8_t seed[MLDSA_CTILDEBYTES])
{
  unsigned int i, j, pos;
  uint64_t signs;
  uint64_t offset;
  MLD_ALIGN uint8_t buf[SHAKE256_RATE];
  keccak_state state;

  shake256_init(&state);
  shake256_absorb(&state, seed, MLDSA_CTILDEBYTES);
  shake256_finalize(&state);
  shake256_squeezeblocks(buf, 1, &state);

  /* Convert the first 8 bytes of buf[] into an unsigned 64-bit value.   */
  /* Each bit of that dictates the sign of the resulting challenge value */
  signs = 0;
  for (i = 0; i < 8; ++i)
  {
    signs |= (uint64_t)buf[i] << 8 * i;
  }
  pos = 8;

  memset(c, 0, sizeof(poly));

  for (i = MLDSA_N - MLDSA_TAU; i < MLDSA_N; ++i)
  {
    do
    {
      if (pos >= SHAKE256_RATE)
      {
        shake256_squeezeblocks(buf, 1, &state);
        pos = 0;
      }
      j = buf[pos++];
    } while (j > i);

    c->coeffs[i] = c->coeffs[j];

    /* Reference: Compute coefficent value here in two steps to */
    /* mixinf unsigned and signed arithmetic with implicit      */
    /* conversions, and so that CBMC can keep track of ranges   */
    /* to complete type-safety proof here.                      */

    /* The least-significant bit of signs tells us if we want -1 or +1 */
    offset = 2 * (signs & 1);

    /* offset has value 0 or 2 here, so (1 - (int32_t) offset) has
     * value -1 or +1 */
    c->coeffs[j] = 1 - (int32_t)offset;

    /* Move to the next bit of signs for next time */
    signs >>= 1;
  }
}

static void polyeta_pack(uint8_t *r, const poly *a)
{
  unsigned int i;
  uint8_t t[8];

  for (i = 0; i < MLDSA_N / 8; ++i)
  {
    t[0] = MLDSA_ETA - a->coeffs[8 * i + 0];
    t[1] = MLDSA_ETA - a->coeffs[8 * i + 1];
    t[2] = MLDSA_ETA - a->coeffs[8 * i + 2];
    t[3] = MLDSA_ETA - a->coeffs[8 * i + 3];
    t[4] = MLDSA_ETA - a->coeffs[8 * i + 4];
    t[5] = MLDSA_ETA - a->coeffs[8 * i + 5];
    t[6] = MLDSA_ETA - a->coeffs[8 * i + 6];
    t[7] = MLDSA_ETA - a->coeffs[8 * i + 7];

    r[3 * i + 0] = ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6)) & 0xFF;
    r[3 * i + 1] =
        ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF;
    r[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF;
  }
}

static void polyeta_unpack(poly *r, const uint8_t *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N / 8; ++i)
  {
    r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
    r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
    r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
    r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
    r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
    r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
    r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
    r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

    r->coeffs[8 * i + 0] = MLDSA_ETA - r->coeffs[8 * i + 0];
    r->coeffs[8 * i + 1] = MLDSA_ETA - r->coeffs[8 * i + 1];
    r->coeffs[8 * i + 2] = MLDSA_ETA - r->coeffs[8 * i + 2];
    r->coeffs[8 * i + 3] = MLDSA_ETA - r->coeffs[8 * i + 3];
    r->coeffs[8 * i + 4] = MLDSA_ETA - r->coeffs[8 * i + 4];
    r->coeffs[8 * i + 5] = MLDSA_ETA - r->coeffs[8 * i + 5];
    r->coeffs[8 * i + 6] = MLDSA_ETA - r->coeffs[8 * i + 6];
    r->coeffs[8 * i + 7] = MLDSA_ETA - r->coeffs[8 * i + 7];
  }
}

static void polyt1_pack(uint8_t *r, const poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N / 4; ++i)
  {
    r[5 * i + 0] = (a->coeffs[4 * i + 0] >> 0) & 0xFF;
    r[5 * i + 1] =
        ((a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2)) & 0xFF;
    r[5 * i + 2] =
        ((a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4)) & 0xFF;
    r[5 * i + 3] =
        ((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6)) & 0xFF;
    r[5 * i + 4] = (a->coeffs[4 * i + 3] >> 2) & 0xFF;
  }
}

static void polyt1_unpack(poly *r, const uint8_t *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N / 4; ++i)
  {
    r->coeffs[4 * i + 0] =
        ((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
    r->coeffs[4 * i + 1] =
        ((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
    r->coeffs[4 * i + 2] =
        ((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
    r->coeffs[4 * i + 3] =
        ((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
  }
}

static void polyt0_pack(uint8_t *r, const poly *a)
{
  unsigned int i;
  uint32_t t[8];

  for (i = 0; i < MLDSA_N / 8; ++i)
  {
    t[0] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 0];
    t[1] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 1];
    t[2] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 2];
    t[3] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 3];
    t[4] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 4];
    t[5] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 5];
    t[6] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 6];
    t[7] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 7];

    r[13 * i + 0] = (t[0]) & 0xFF;
    r[13 * i + 1] = (t[0] >> 8) & 0xFF;
    r[13 * i + 1] |= (t[1] << 5) & 0xFF;
    r[13 * i + 2] = (t[1] >> 3) & 0xFF;
    r[13 * i + 3] = (t[1] >> 11) & 0xFF;
    r[13 * i + 3] |= (t[2] << 2) & 0xFF;
    r[13 * i + 4] = (t[2] >> 6) & 0xFF;
    r[13 * i + 4] |= (t[3] << 7) & 0xFF;
    r[13 * i + 5] = (t[3] >> 1) & 0xFF;
    r[13 * i + 6] = (t[3] >> 9) & 0xFF;
    r[13 * i + 6] |= (t[4] << 4) & 0xFF;
    r[13 * i + 7] = (t[4] >> 4) & 0xFF;
    r[13 * i + 8] = (t[4] >> 12) & 0xFF;
    r[13 * i + 8] |= (t[5] << 1) & 0xFF;
    r[13 * i + 9] = (t[5] >> 7) & 0xFF;
    r[13 * i + 9] |= (t[6] << 6) & 0xFF;
    r[13 * i + 10] = (t[6] >> 2) & 0xFF;
    r[13 * i + 11] = (t[6] >> 10) & 0xFF;
    r[13 * i + 11] |= (t[7] << 3) & 0xFF;
    r[13 * i + 12] = (t[7] >> 5) & 0xFF;
  }
}

static void polyt0_unpack(poly *r, const uint8_t *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N / 8; ++i)
  {
    r->coeffs[8 * i + 0] = a[13 * i + 0];
    r->coeffs[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
    r->coeffs[8 * i + 0] &= 0x1FFF;

    r->coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
    r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
    r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
    r->coeffs[8 * i + 1] &= 0x1FFF;

    r->coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
    r->coeffs[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
    r->coeffs[8 * i + 2] &= 0x1FFF;

    r->coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
    r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
    r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
    r->coeffs[8 * i + 3] &= 0x1FFF;

    r->coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
    r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
    r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
    r->coeffs[8 * i + 4] &= 0x1FFF;

    r->coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
    r->coeffs[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
    r->coeffs[8 * i + 5] &= 0x1FFF;

    r->coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
    r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
    r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
    r->coeffs[8 * i + 6] &= 0x1FFF;

    r->coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
    r->coeffs[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
    r->coeffs[8 * i + 7] &= 0x1FFF;

    r->coeffs[8 * i + 0] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 0];
    r->coeffs[8 * i + 1] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 1];
    r->coeffs[8 * i + 2] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 2];
    r->coeffs[8 * i + 3] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 3];
    r->coeffs[8 * i + 4] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 4];
    r->coeffs[8 * i + 5] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 5];
    r->coeffs[8 * i + 6] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 6];
    r->coeffs[8 * i + 7] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 7];
  }
}

static void polyz_pack(uint8_t *r, const poly *a)
{
  unsigned int i;
  uint32_t t[4];

  for (i = 0; i < MLDSA_N / 4; ++i)
  {
    t[0] = MLDSA_GAMMA1 - a->coeffs[4 * i + 0];
    t[1] = MLDSA_GAMMA1 - a->coeffs[4 * i + 1];
    t[2] = MLDSA_GAMMA1 - a->coeffs[4 * i + 2];
    t[3] = MLDSA_GAMMA1 - a->coeffs[4 * i + 3];

    r[9 * i + 0] = (t[0]) & 0xFF;
    r[9 * i + 1] = (t[0] >> 8) & 0xFF;
    r[9 * i + 2] = (t[0] >> 16) & 0xFF;
    r[9 * i + 2] |= (t[1] << 2) & 0xFF;
    r[9 * i + 3] = (t[1] >> 6) & 0xFF;
    r[9 * i + 4] = (t[1] >> 14) & 0xFF;
    r[9 * i + 4] |= (t[2] << 4) & 0xFF;
    r[9 * i + 5] = (t[2] >> 4) & 0xFF;
    r[9 * i + 6] = (t[2] >> 12) & 0xFF;
    r[9 * i + 6] |= (t[3] << 6) & 0xFF;
    r[9 * i + 7] = (t[3] >> 2) & 0xFF;
    r[9 * i + 8] = (t[3] >> 10) & 0xFF;
  }
}

static void polyw1_pack(uint8_t *r, const poly *a)
{
  unsigned int i;

  for (i = 0; i < MLDSA_N / 4; ++i)
  {
    r[3 * i + 0] = (a->coeffs[4 * i + 0]) & 0xFF;
    r[3 * i + 0] |= (a->coeffs[4 * i + 1] << 6) & 0xFF;
    r[3 * i + 1] = (a->coeffs[4 * i + 1] >> 2) & 0xFF;
    r[3 * i + 1] |= (a->coeffs[4 * i + 2] << 4) & 0xFF;
    r[3 * i + 2] = (a->coeffs[4 * i + 2] >> 4) & 0xFF;
    r[3 * i + 2] |= (a->coeffs[4 * i + 3] << 2) & 0xFF;
  }
}

static void
polyvec_matrix_expand(polyvecl mat[MLDSA_K],
                      const uint8_t rho[MLDSA_SEEDBYTES])
{
  unsigned int i, j;
  /*
   * We generate four separate seed arrays rather than a single one to work
   * around limitations in CBMC function contracts dealing with disjoint slices
   * of the same parent object.
   */

  MLD_ALIGN uint8_t seed_ext[4][MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)];

  for (j = 0; j < 4; j++)
  {
    memcpy(seed_ext[j], rho, MLDSA_SEEDBYTES);
  }
  /* Sample 4 matrix entries a time. */
  for (i = 0; i < (MLDSA_K * MLDSA_L / 4) * 4; i += 4)
  {
    for (j = 0; j < 4; j++)
    {
      uint8_t x = (i + j) / MLDSA_L;
      uint8_t y = (i + j) % MLDSA_L;

      seed_ext[j][MLDSA_SEEDBYTES + 0] = y;
      seed_ext[j][MLDSA_SEEDBYTES + 1] = x;
    }

    poly_uniform_4x(&mat[i / MLDSA_L].vec[i % MLDSA_L],
                    &mat[(i + 1) / MLDSA_L].vec[(i + 1) % MLDSA_L],
                    &mat[(i + 2) / MLDSA_L].vec[(i + 2) % MLDSA_L],
                    &mat[(i + 3) / MLDSA_L].vec[(i + 3) % MLDSA_L], seed_ext);
  }

  /* For MLDSA_K=6, MLDSA_L=5, process the last two entries individually */
  while (i < MLDSA_K * MLDSA_L)
  {
    uint8_t x = i / MLDSA_L;
    uint8_t y = i % MLDSA_L;
    poly *this_poly = &mat[i / MLDSA_L].vec[i % MLDSA_L];

    seed_ext[0][MLDSA_SEEDBYTES + 0] = y;
    seed_ext[0][MLDSA_SEEDBYTES + 1] = x;

    poly_uniform(this_poly, seed_ext[0]);
    i++;
  }
}

/**************************************************************/
/************ Vectors of polynomials of length MLDSA_L **************/
/**************************************************************/
static void
polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES],
                        uint16_t nonce)
{
  nonce = MLDSA_L * nonce;
  poly_uniform_gamma1_4x(&v->vec[0], &v->vec[1], &v->vec[2], &v->vec[3], seed,
                         nonce, nonce + 1, nonce + 2, nonce + 3);
}

static void polyvecl_reduce(polyvecl *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_L; ++i)
  {
    poly_reduce(&v->vec[i]);
  }
}

/* Reference: We use destructive version (output=first input) to avoid
 *            reasoning about aliasing in the CBMC specification */
static void polyvecl_add(polyvecl *u, const polyvecl *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_L; ++i)
  {
    poly_add(&u->vec[i], &v->vec[i]);
  }
}

static void polyvecl_ntt(polyvecl *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_L; ++i)
  {
    poly_ntt(&v->vec[i]);
  }
}

static void polyvecl_invntt_tomont(polyvecl *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_L; ++i)
  {
    poly_invntt_tomont(&v->vec[i]);
  }
}

static void
polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a,
                                   const polyvecl *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_L; ++i)
  {
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
  }
}

static void
polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
                                  const polyvecl *v)
{
  unsigned int i, j;
  /* The first input is bounded by [0, Q-1] inclusive
   * The second input is bounded by [-9Q+1, 9Q-1] inclusive . Hence, we can
   * safely accumulate in 64-bits without intermediate reductions as
   * MLDSA_L * (MLD_NTT_BOUND-1) * (Q-1) < INT64_MAX
   *
   * The worst case is ML-DSA-87: 7 * (9Q-1) * (Q-1) < 2**52
   * (and likewise for negative values)
   */

  for (i = 0; i < MLDSA_N; i++)
  {
    int64_t t = 0;
    int32_t r;
    for (j = 0; j < MLDSA_L; j++)
    {
      t += (int64_t)u->vec[j].coeffs[i] * v->vec[j].coeffs[i];
    }

    r = montgomery_reduce(t);

    w->coeffs[i] = r;
  }
}


static int polyvecl_chknorm(const polyvecl *v, int32_t bound)
{
  unsigned int i;

  for (i = 0; i < MLDSA_L; ++i)
  {
    if (poly_chknorm(&v->vec[i], bound))
    {
      return 1;
    }
  }

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length MLDSA_K **************/
/**************************************************************/

static void polyveck_reduce(polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_reduce(&v->vec[i]);
  }
}

static void polyveck_caddq(polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_caddq(&v->vec[i]);
  }
}

/* Reference: We use destructive version (output=first input) to avoid
 *            reasoning about aliasing in the CBMC specification */
static void polyveck_add(polyveck *u, const polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_add(&u->vec[i], &v->vec[i]);
  }
}

static void polyveck_sub(polyveck *u, const polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_sub(&u->vec[i], &v->vec[i]);
  }
}

static void polyveck_shiftl(polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_shiftl(&v->vec[i]);
  }
}

static void polyveck_ntt(polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_ntt(&v->vec[i]);
  }
}

static void polyveck_invntt_tomont(polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_invntt_tomont(&v->vec[i]);
  }
}

static void
polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a,
                                   const polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
  }
}


static int polyveck_chknorm(const polyveck *v, int32_t bound)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    if (poly_chknorm(&v->vec[i], bound))
    {
      return 1;
    }
  }

  return 0;
}

static void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
  }
}

static void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
  }
}

static unsigned int
polyveck_make_hint(polyveck *h, const polyveck *v0,
                   const polyveck *v1)
{
  unsigned int i, s = 0;

  for (i = 0; i < MLDSA_K; ++i)
  {
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
  }

  return s;
}

static void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
  }
}

static void
polyveck_pack_w1(uint8_t r[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES],
                 const polyveck *w1)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    polyw1_pack(&r[i * MLDSA_POLYW1_PACKEDBYTES], &w1->vec[i]);
  }
}

static void
polyveck_pack_eta(uint8_t r[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES],
                  const polyveck *p)
{
  unsigned int i;
  for (i = 0; i < MLDSA_K; ++i)
  {
    polyeta_pack(r + i * MLDSA_POLYETA_PACKEDBYTES, &p->vec[i]);
  }
}

static void
polyvecl_pack_eta(uint8_t r[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES],
                  const polyvecl *p)
{
  unsigned int i;
  for (i = 0; i < MLDSA_L; ++i)
  {
    polyeta_pack(r + i * MLDSA_POLYETA_PACKEDBYTES, &p->vec[i]);
  }
}

static void
polyvecl_pack_z(uint8_t r[MLDSA_L * MLDSA_POLYZ_PACKEDBYTES],
                const polyvecl *p)
{
  unsigned int i;
  for (i = 0; i < MLDSA_L; ++i)
  {
    polyz_pack(r + i * MLDSA_POLYZ_PACKEDBYTES, &p->vec[i]);
  }
}


static void
polyveck_pack_t0(uint8_t r[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES],
                 const polyveck *p)
{
  unsigned int i;
  for (i = 0; i < MLDSA_K; ++i)
  {
    polyt0_pack(r + i * MLDSA_POLYT0_PACKEDBYTES, &p->vec[i]);
  }
}

static void
polyvecl_unpack_eta(polyvecl *p,
                    const uint8_t r[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES])
{
  unsigned int i;
  for (i = 0; i < MLDSA_L; ++i)
  {
    polyeta_unpack(&p->vec[i], r + i * MLDSA_POLYETA_PACKEDBYTES);
  }
}

static void
polyvecl_unpack_z(polyvecl *z,
                  const uint8_t r[MLDSA_L * MLDSA_POLYZ_PACKEDBYTES])
{
  unsigned int i;
  for (i = 0; i < MLDSA_L; ++i)
  {
    polyz_unpack(&z->vec[i], r + i * MLDSA_POLYZ_PACKEDBYTES);
  }
}

static void
polyveck_unpack_eta(polyveck *p,
                    const uint8_t r[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES])
{
  unsigned int i;
  for (i = 0; i < MLDSA_K; ++i)
  {
    polyeta_unpack(&p->vec[i], r + i * MLDSA_POLYETA_PACKEDBYTES);
  }
}

static void
polyveck_unpack_t0(polyveck *p,
                   const uint8_t r[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES])
{
  unsigned int i;
  for (i = 0; i < MLDSA_K; ++i)
  {
    polyt0_unpack(&p->vec[i], r + i * MLDSA_POLYT0_PACKEDBYTES);
  }
}

static void
polyvec_matrix_pointwise_montgomery(polyveck *t,
                                    const polyvecl mat[MLDSA_K],
                                    const polyvecl *v)
{
  unsigned int i;

  for (i = 0; i < MLDSA_K; ++i)
  {
    polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
  }
}

static void mld_sample_s1_s2(polyvecl *s1, polyveck *s2,
                             const uint8_t seed[MLDSA_CRHBYTES])
{
/* Sample short vectors s1 and s2 */
  poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3], seed,
                      0, 1, 2, 3);
  poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3], seed,
                      4, 5, 6, 7);
}

static void
pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
        const uint8_t rho[MLDSA_SEEDBYTES], const polyveck *t1)
{
  unsigned int i;

  memcpy(pk, rho, MLDSA_SEEDBYTES);
  pk += MLDSA_SEEDBYTES;

  for (i = 0; i < MLDSA_K; ++i)
  {
    polyt1_pack(pk + i * MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
  }
}

static void
unpack_pk(uint8_t rho[MLDSA_SEEDBYTES], polyveck *t1,
          const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

  memcpy(rho, pk, MLDSA_SEEDBYTES);
  pk += MLDSA_SEEDBYTES;

  for (i = 0; i < MLDSA_K; ++i)
  {
    polyt1_unpack(&t1->vec[i], pk + i * MLDSA_POLYT1_PACKEDBYTES);
  }
}

static void
pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
        const uint8_t rho[MLDSA_SEEDBYTES],
        const uint8_t tr[MLDSA_TRBYTES],
        const uint8_t key[MLDSA_SEEDBYTES], const polyveck *t0,
        const polyvecl *s1, const polyveck *s2)
{
  memcpy(sk, rho, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(sk, key, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(sk, tr, MLDSA_TRBYTES);
  sk += MLDSA_TRBYTES;

  polyvecl_pack_eta(sk, s1);
  sk += MLDSA_L * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_pack_eta(sk, s2);
  sk += MLDSA_K * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_pack_t0(sk, t0);
}

static void
unpack_sk(uint8_t rho[MLDSA_SEEDBYTES], uint8_t tr[MLDSA_TRBYTES],
          uint8_t key[MLDSA_SEEDBYTES], polyveck *t0, polyvecl *s1,
          polyveck *s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  memcpy(rho, sk, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(key, sk, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(tr, sk, MLDSA_TRBYTES);
  sk += MLDSA_TRBYTES;

  polyvecl_unpack_eta(s1, sk);
  sk += MLDSA_L * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_unpack_eta(s2, sk);
  sk += MLDSA_K * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_unpack_t0(t0, sk);
}

static void
pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[MLDSA_CTILDEBYTES],
         const polyvecl *z, const polyveck *h,
         const unsigned int number_of_hints)
{
  unsigned int i, j, k;

  memcpy(sig, c, MLDSA_CTILDEBYTES);
  sig += MLDSA_CTILDEBYTES;

  polyvecl_pack_z(sig, z);
  sig += MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;

  /* Encode hints h */

  /* The final section of sig[] is MLDSA_POLYVECH_PACKEDBYTES long, where
   * MLDSA_POLYVECH_PACKEDBYTES = MLDSA_OMEGA + MLDSA_K
   *
   * The first OMEGA bytes record the index numbers of the coefficients
   * that are not equal to 0
   *
   * The final K bytes record a running tally of the number of hints
   * coming from each of the K polynomials in h.
   *
   * The pre-condition tells us that number_of_hints <= OMEGA, so some
   * bytes may not be written, so we initialize all of them to zero
   * to start.
   */
  memset(sig, 0, MLDSA_POLYVECH_PACKEDBYTES);

  k = 0;
  /* For each polynomial in h... */
  for (i = 0; i < MLDSA_K; ++i)
  {
    /* For each coefficient in that polynomial, record it as as hint */
    /* if its value is not zero */
    for (j = 0; j < MLDSA_N; ++j)
    {
      /* The reference implementation implicitly relies on the total */
      /* number of hints being less than OMEGA, assuming h is valid. */
      /* In mldsa-native, we check this explicitly to ease proof of  */
      /* type safety.                                                */
      if (h->vec[i].coeffs[j] != 0 && k < number_of_hints)
      {
        /* The enclosing if condition AND the loop invariant infer  */
        /* that k < MLDSA_OMEGA, so writing to sig[k] is safe and k */
        /* can be incremented.                                      */
        sig[k++] = j;
      }
    }
    /* Having recorded all the hints for this polynomial, also   */
    /* record the running tally into the correct "slot" for that */
    /* coefficient in the final K bytes                          */
    sig[MLDSA_OMEGA + i] = k;
  }
}

/*************************************************
 * Name:        unpack_hints
 *
 * Description: Unpack raw hint bytes into a polyveck
 *              struct
 *
 * Arguments:   - polyveck *h: pointer to output hint vector h
 *              - const uint8_t packed_hints[MLDSA_POLYVECH_PACKEDBYTES]:
 *                raw hint bytes
 *
 * Returns 1 in case of malformed hints; otherwise 0.
 **************************************************/
static int unpack_hints(polyveck *h,
                        const uint8_t packed_hints[MLDSA_POLYVECH_PACKEDBYTES])
{
  unsigned int i, j;
  unsigned int old_hint_count;

  /* Set all coefficients of all polynomials to 0.    */
  /* Only those that are actually non-zero hints will */
  /* be overwritten below.                            */
  memset(h, 0, sizeof(polyveck));

  old_hint_count = 0;
  for (i = 0; i < MLDSA_K; ++i)
  {
    /* Grab the hint count for the i'th polynomial */
    const unsigned int new_hint_count = packed_hints[MLDSA_OMEGA + i];

    /* new_hint_count must increase or stay the same, but also remain */
    /* less than or equal to MLDSA_OMEGA                              */
    if (new_hint_count < old_hint_count || new_hint_count > MLDSA_OMEGA)
    {
      /* Error - new_hint_count is invalid */
      return 1;
    }

    /* If new_hint_count == old_hint_count, then this polynomial has */
    /* zero hints, so this loop executes zero times and we move      */
    /* straight on to the next polynomial.                           */
    for (j = old_hint_count; j < new_hint_count; ++j)
    {
      const uint8_t this_hint_index = packed_hints[j];

      /* Coefficients must be ordered for strong unforgeability */
      if (j > old_hint_count && this_hint_index <= packed_hints[j - 1])
      {
        return 1;
      }
      h->vec[i].coeffs[this_hint_index] = 1;
    }

    old_hint_count = new_hint_count;
  }

  /* Extra indices must be zero for strong unforgeability */
  for (j = old_hint_count; j < MLDSA_OMEGA; ++j)
  {
    if (packed_hints[j] != 0)
    {
      return 1;
    }
  }

  return 0;
}

static int
unpack_sig(uint8_t c[MLDSA_CTILDEBYTES], polyvecl *z, polyveck *h,
           const uint8_t sig[CRYPTO_BYTES])
{
  memcpy(c, sig, MLDSA_CTILDEBYTES);
  sig += MLDSA_CTILDEBYTES;

  polyvecl_unpack_z(z, sig);
  sig += MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;

  return unpack_hints(h, sig);
}

static int
crypto_sign_keypair_internal(uint8_t *pk, uint8_t *sk,
			     const uint8_t seed[MLDSA_SEEDBYTES])
{
  uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
  uint8_t inbuf[MLDSA_SEEDBYTES + 2];
  uint8_t tr[MLDSA_TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[MLDSA_K];
  polyvecl s1, s1hat;
  polyveck s2, t2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  memcpy(inbuf, seed, MLDSA_SEEDBYTES);
  inbuf[MLDSA_SEEDBYTES + 0] = MLDSA_K;
  inbuf[MLDSA_SEEDBYTES + 1] = MLDSA_L;
  shake256(seedbuf, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, inbuf,
           MLDSA_SEEDBYTES + 2);
  rho = seedbuf;
  rhoprime = rho + MLDSA_SEEDBYTES;
  key = rhoprime + MLDSA_CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  mld_sample_s1_s2(&s1, &s2, rhoprime);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t2, &t0, &t1);
  pack_pk(pk, rho, &t2);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, MLDSA_TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
  return 0;
}

int MLD_44_ref_pubkey(uint8_t *pk, const uint8_t *sk)
{
  uint8_t rho[MLDSA_SEEDBYTES];
  uint8_t key[MLDSA_SEEDBYTES];
  uint8_t tr[MLDSA_TRBYTES];
  polyvecl mat[MLDSA_K];
  polyvecl s1;
  polyveck s2, t2, t1, t0;

  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Matrix-vector multiplication */
  polyvecl_ntt(&s1);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t2, &t0, &t1);
  pack_pk(pk, rho, &t2);
  return 0;
}

int MLD_44_ref_keypair(uint8_t *pk, uint8_t *sk)
{
  uint8_t seed[MLDSA_SEEDBYTES];
  randombytes(seed, MLDSA_SEEDBYTES);
  return crypto_sign_keypair_internal(pk, sk, seed);
}

/*************************************************
 * Name:        mld_H
 *
 * Description: Abstracts application of SHAKE256 to
 *              one, two or three blocks of data,
 *              yielding a user-requested size of
 *              output.
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *in1: pointer to input block 1
 *                                    Must NOT be NULL
 *              - size_t in1len: length of input in1 bytes
 *              - const uint8_t *in2: pointer to input block 2
 *                                    May be NULL, in which case
 *                                    this block is ignored
 *              - size_t in2len: length of input in2 bytes
 *              - const uint8_t *in3: pointer to input block 3
 *                                    May be NULL, in which case
 *                                    this block is ignored
 *              - size_t in3len: length of input in3 bytes
 **************************************************/
static void mld_H(uint8_t *out, size_t outlen, const uint8_t *in1,
                  size_t in1len, const uint8_t *in2, size_t in2len,
                  const uint8_t *in3, size_t in3len)
{
  keccak_state state;
  shake256_init(&state);
  shake256_absorb(&state, in1, in1len);
  if (in2 != NULL)
  {
    shake256_absorb(&state, in2, in2len);
  }
  if (in3 != NULL)
  {
    shake256_absorb(&state, in3, in3len);
  }
  shake256_finalize(&state);
  shake256_squeeze(out, outlen, &state);
}

static int
crypto_sign_signature_internal(uint8_t *sig, size_t *siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *pre, size_t prelen,
                               const uint8_t rnd[MLDSA_RNDBYTES],
                               const uint8_t *sk, int externalmu)
{
  unsigned int n;
  uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[MLDSA_K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;

  rho = seedbuf;
  tr = rho + MLDSA_SEEDBYTES;
  key = tr + MLDSA_TRBYTES;
  mu = key + MLDSA_SEEDBYTES;
  rhoprime = mu + MLDSA_CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  if (!externalmu)
  {
    /* Compute mu = CRH(tr, pre, msg) */
    mld_H(mu, MLDSA_CRHBYTES, tr, MLDSA_TRBYTES, pre, prelen, m, mlen);
  }
  else
  {
    /* mu has been provided directly */
    memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* Compute rhoprime = CRH(key, rnd, mu) */
  mld_H(rhoprime, MLDSA_CRHBYTES, key, MLDSA_SEEDBYTES, rnd, MLDSA_RNDBYTES, mu,
        MLDSA_CRHBYTES);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

  /* Reference: This code is re-structured using a while(1),  */
  /* with explicit "continue" statements (rather than "goto") */
  /* to implement rejection of invalid signatures.            */
  /* The loop statement also supplies a syntactic location to */
  /* place loop invariants for CBMC.                          */
  while (1)
  {
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq(&w1);
    polyveck_decompose(&w1, &w0, &w1);
    polyveck_pack_w1(sig, &w1);

    mld_H(sig, MLDSA_CTILDEBYTES, mu, MLDSA_CRHBYTES, sig,
          MLDSA_K * MLDSA_POLYW1_PACKEDBYTES, NULL, 0);
    poly_challenge(&cp, sig);
    poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    polyvecl_invntt_tomont(&z);
    polyvecl_add(&z, &y);
    polyvecl_reduce(&z);
    if (polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
    {
      /* reject */
      continue;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    polyveck_invntt_tomont(&h);
    polyveck_sub(&w0, &h);
    polyveck_reduce(&w0);
    if (polyveck_chknorm(&w0, MLDSA_GAMMA2 - MLDSA_BETA))
    {
      /* reject */
      continue;
    }

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    polyveck_invntt_tomont(&h);
    polyveck_reduce(&h);
    if (polyveck_chknorm(&h, MLDSA_GAMMA2))
    {
      /* reject */
      continue;
    }

    polyveck_add(&w0, &h);
    n = polyveck_make_hint(&h, &w0, &w1);
    if (n > MLDSA_OMEGA)
    {
      /* reject */
      continue;
    }

    /* Write signature */
    pack_sig(sig, sig, &z, &h, n);
    *siglen = CRYPTO_BYTES;
    return 0;
  }
}

int MLD_44_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                         size_t mlen, const uint8_t *ctx, size_t ctxlen,
                         const uint8_t *sk)
{
  size_t i;
  uint8_t pre[257];
  uint8_t rnd[MLDSA_RNDBYTES];

  if (ctxlen > 255)
  {
    return -1;
  }

  /* Prepare pre = (0, ctxlen, ctx) */
  pre[0] = 0;
  pre[1] = ctxlen;
  for (i = 0; i < ctxlen; i++)
  {
    pre[2 + i] = ctx[i];
  }

  randombytes(rnd, MLDSA_RNDBYTES);

  crypto_sign_signature_internal(sig, siglen, m, mlen, pre, 2 + ctxlen, rnd, sk,
                                 0);
  return 0;
}

int MLD_44_ref(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
               const uint8_t *ctx, size_t ctxlen, const uint8_t *sk)
{
  int ret;
  size_t i;

  for (i = 0; i < mlen; ++i)
  {
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  }
  ret = MLD_44_ref_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, ctx, ctxlen,
                             sk);
  *smlen += mlen;
  return ret;
}

static int
MLD_44_ref_verify_internal(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *pre, size_t prelen,
                            const uint8_t *pk, int externalmu)
{
  unsigned int i;
  uint8_t buf[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
  uint8_t rho[MLDSA_SEEDBYTES];
  uint8_t mu[MLDSA_CRHBYTES];
  uint8_t c[MLDSA_CTILDEBYTES];
  uint8_t c2[MLDSA_CTILDEBYTES];
  poly cp;
  polyvecl mat[MLDSA_K], z;
  polyveck t1, w1, tmp, h;

  if (siglen != CRYPTO_BYTES)
  {
    return -1;
  }

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
  {
    return -1;
  }
  if (polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
  {
    return -1;
  }

  if (!externalmu)
  {
    /* Compute CRH(H(rho, t1), pre, msg) */
    uint8_t hpk[MLDSA_CRHBYTES];
    mld_H(hpk, MLDSA_TRBYTES, pk, CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL, 0);
    mld_H(mu, MLDSA_CRHBYTES, hpk, MLDSA_TRBYTES, pre, prelen, m, mlen);
  }
  else
  {
    /* mu has been provided directly */
    memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);

  polyveck_pointwise_poly_montgomery(&tmp, &cp, &t1);

  polyveck_sub(&w1, &tmp);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&tmp, &w1, &h);
  polyveck_pack_w1(buf, &tmp);
  /* Call random oracle and verify challenge */
  mld_H(c2, MLDSA_CTILDEBYTES, mu, MLDSA_CRHBYTES, buf,
        MLDSA_K * MLDSA_POLYW1_PACKEDBYTES, NULL, 0);
  for (i = 0; i < MLDSA_CTILDEBYTES; ++i)
  {
    if (c[i] != c2[i])
    {
      return -1;
    }
  }
  return 0;
}

int MLD_44_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                      size_t mlen, const uint8_t *ctx, size_t ctxlen,
                      const uint8_t *pk)
{
  size_t i;
  uint8_t pre[257];

  if (ctxlen > 255)
  {
    return -1;
  }

  pre[0] = 0;
  pre[1] = ctxlen;
  for (i = 0; i < ctxlen; i++)
  {
    pre[2 + i] = ctx[i];
  }

  return MLD_44_ref_verify_internal(sig, siglen, m, mlen, pre, 2 + ctxlen, pk,
                                     0);
}

int MLD_44_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
{
  size_t i;

  if (smlen < CRYPTO_BYTES)
  {
    goto badsig;
  }

  *mlen = smlen - CRYPTO_BYTES;
  if (MLD_44_ref_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, ctx,
                         ctxlen, pk))
  {
    goto badsig;
  }
  else
  {
    /* All good, copy msg, return 0 */
    for (i = 0; i < *mlen; ++i)
    {
      m[i] = sm[CRYPTO_BYTES + i];
    }
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = 0;
  for (i = 0; i < smlen; ++i)
  {
    m[i] = 0;
  }

  return -1;
}
