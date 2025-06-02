/*
Original code: supercop/crypto_kem/sntrup761/ref
*/

/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#include <string.h>
#include <stdint.h>
#include "random.h"
#include "sha512.h"
#include "sntrup761.h"
#include <stdio.h>

static int crypto_hash_sha512(uint8_t *dest, const uint8_t *src, size_t len)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, src, len);
	sha512_final(&s, dest);

	return 0;
}

/* crypto_sort_uint32.c from tinyssh */

static void minmax(uint32_t *x, uint32_t *y) {

    uint32_t xi = *x;
    uint32_t yi = *y;
    uint32_t xy = xi ^ yi;
    uint32_t c = yi - xi;

    c ^= xy & (c ^ yi ^ 0x80000000);
    c >>= 31;
    c &= 1;
    c = -c;
    c &= xy;
    *x = xi ^ c;
    *y = yi ^ c;
}

static void crypto_sort_uint32(void *xv, ssize_t n) {

    ssize_t top, p, q, i;
    uint32_t *x = xv;

    if (n < 2) return;
    top = 1;
    while (top < n - top) top += top;

    for (p = top; p > 0; p >>= 1) {
        for (i = 0; i < n - p; ++i)
            if (!(i & p)) minmax(x + i, x + i + p);
        for (q = top; q > p; q >>= 1)
            for (i = 0; i < n - q; ++i)
                if (!(i & p)) minmax(x + i + p, x + i + q);
    }
}

/* crypto_int16.h */
volatile int16_t crypto_int16_optblocker = 0;

static inline
int16_t crypto_int16_negative_mask(int16_t crypto_int16_x) {
#if defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  return crypto_int16_x;
#elif defined(__GNUC__) && defined(__aarch64__)
  int16_t crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) :);
  return crypto_int16_y;
#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && !defined(__thumb__)
  int16_t crypto_int16_y;
  __asm__ ("sxth %0,%1\n asr %0,%0,#31" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) :);
  return crypto_int16_y;
#elif defined(__GNUC__) && defined(__sparc_v8__)
  int16_t crypto_int16_y;
  __asm__ ("sll %1,16,%0\n sra %0,31,%0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) :);
  return crypto_int16_y;
#else
  crypto_int16_x >>= 16-6;
  crypto_int16_x += crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  return crypto_int16_x;
#endif
}

static inline
int16_t crypto_int16_nonzero_mask(int16_t crypto_int16_x) {
#if defined(__GNUC__) && defined(__x86_64__)
  int16_t crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  return crypto_int16_z;
#elif defined(__GNUC__) && defined(__aarch64__)
  int16_t crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  return crypto_int16_z;
#elif defined(__GNUC__) && defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && !defined(__thumb__)
  __asm__ ("uxth %0,%0\n cmp %0,#0\n movne %0,#-1" : "+r"(crypto_int16_x) : : "cc");
  return crypto_int16_x;
#elif defined(__GNUC__) && defined(__sparc_v8__)
  int16_t crypto_int16_z;
  __asm__ ("sll %0,16,%0\n srl %0,16,%0\n cmp %%g0,%0\n subx %%g0,0,%1" : "+r"(crypto_int16_x), "=r"(crypto_int16_z) : : "cc");
  return crypto_int16_z;
#else
  crypto_int16_x |= -crypto_int16_x;
  return crypto_int16_negative_mask(crypto_int16_x);
#endif
}


/* uint32.c */

/*
CPU division instruction typically takes time depending on x.
This software is designed to take time independent of x.
Time still varies depending on m; user must ensure that m is constant.
Time also varies on CPUs where multiplication is variable-time.
There could be more CPU issues.
There could also be compiler issues.
*/

static void uint32_divmod_uint14(uint32_t *q, uint16_t *r, uint32_t x, uint16_t m) {
    uint32_t v = 0x80000000;
    uint32_t qpart;
    uint32_t mask;

    v /= m;

    /* caller guarantees m > 0 */
    /* caller guarantees m < 16384 */
    /* vm <= 2^31 <= vm+m-1 */
    /* xvm <= 2^31 x <= xvm+x(m-1) */

    *q = 0;

    qpart = (x * (uint64_t) v) >> 31;
    /* 2^31 qpart <= xv <= 2^31 qpart + 2^31-1 */
    /* 2^31 qpart m <= xvm <= 2^31 qpart m + (2^31-1)m */
    /* 2^31 qpart m <= 2^31 x <= 2^31 qpart m + (2^31-1)m + x(m-1) */
    /* 0 <= 2^31 newx <= (2^31-1)m + x(m-1) */
    /* 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31 */
    /* 0 <= newx <= (1-1/2^31)(2^14-1) + (2^32-1)((2^14-1)-1)/2^31 */

    x -= qpart * m;
    *q += qpart;
    /* x <= 49146 */

    qpart = (x * (uint64_t) v) >> 31;
    /* 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31 */
    /* 0 <= newx <= m + 49146(2^14-1)/2^31 */
    /* 0 <= newx <= m + 0.4 */
    /* 0 <= newx <= m */

    x -= qpart * m;
    *q += qpart;
    /* x <= m */

    x -= m;
    *q += 1;
    mask = -(x >> 31);
    x += mask & (uint32_t) m;
    *q += mask;
    /* x < m */

    *r = x;
}

static uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
    uint32_t q;
    uint16_t r;
    uint32_divmod_uint14(&q, &r, x, m);
    return r;
}

/* params.h */

#define qinv 15631 /* reciprocal of q mod 2^16 */
#define q31 467759 /* floor(2^31/q) */
#define q27 29235 /* closest integer to 2^27/q */
#define q18 57 /* closest integer to 2^18/q */
#define q15 7 /* round(2^15/q) */
#define q14 4 /* closest integer to 2^14/q */

#define p 761
#define q 4591
#define Rounded_bytes 1007
#define Rq_bytes 1158
#define w 286

/* crypto_core_wforce.c */

/* 0 if Weightw_is(r), else -1 */
static int Weightw_mask(const int8_t *r) {
    int weight = 0;
    int i;

    for (i = 0; i < p; ++i) {
        weight += r[i] & 1;
    }
    return crypto_int16_nonzero_mask((int16_t) (weight - w));
}

/* out = in if bottom bits of in have weight w */
/* otherwise out = (1,1,...,1,0,0,...,0) */
static int crypto_core_wforce(uint8_t *outbytes, const uint8_t *inbytes)
{
    int8_t *out = (void *) outbytes;
    const int8_t *in = (const void *) inbytes;
    int i, mask;

    mask = Weightw_mask(in); /* 0 if weight w, else -1 */
    for (i = 0; i < w; ++i) {
        out[i] = (int8_t) (((in[i] ^ 1) & ~mask) ^ 1);
    }
    for (i = w; i < p; ++i) {
        out[i] = (int8_t) (in[i] & ~mask);
    }
    return 0;
}

/* Decode.c */

static void Decode(uint16_t *out, const uint8_t *S, const uint16_t *M,
                   ssize_t len) {
    if (len == 1) {
        if (M[0] == 1)
            *out = 0;
        else if (M[0] <= 256)
            *out = uint32_mod_uint14(S[0], M[0]);
        else
            *out = uint32_mod_uint14(S[0] + (((uint16_t) S[1]) << 8), M[0]);
    }
    if (len > 1) {
        uint16_t R2[(len + 1) / 2];
        uint16_t M2[(len + 1) / 2];
        uint16_t bottomr[len / 2];
        uint32_t bottomt[len / 2];
        ssize_t i;
        for (i = 0; i < len - 1; i += 2) {
            uint32_t m = M[i] * (uint32_t) M[i + 1];
            if (m > 256 * 16383) {
                bottomt[i / 2] = 256 * 256;
                bottomr[i / 2] = S[0] + 256 * S[1];
                S += 2;
                M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
            }
            else if (m >= 16384) {
                bottomt[i / 2] = 256;
                bottomr[i / 2] = S[0];
                S += 1;
                M2[i / 2] = (m + 255) >> 8;
            }
            else {
                bottomt[i / 2] = 1;
                bottomr[i / 2] = 0;
                M2[i / 2] = m;
            }
        }
        if (i < len) M2[i / 2] = M[i];
        Decode(R2, S, M2, (len + 1) / 2);
        for (i = 0; i < len - 1; i += 2) {
            uint32_t r = bottomr[i / 2];
            uint32_t r1;
            uint16_t r0;
            r += bottomt[i / 2] * R2[i / 2];
            uint32_divmod_uint14(&r1, &r0, r, M[i]);
            r1 = uint32_mod_uint14(
                r1, M[i + 1]); /* only needed for invalid inputs */
            *out++ = r0;
            *out++ = r1;
        }
        if (i < len) *out++ = R2[i / 2];
    }
}

/* Encode.c */

/* 0 <= R[i] < M[i] < 16384 */
static void Encode(uint8_t *out, const uint16_t *R, const uint16_t *M,
                   ssize_t len) {
    if (len == 1) {
        uint16_t r = R[0];
        uint16_t m = M[0];
        while (m > 1) {
            *out++ = r;
            r >>= 8;
            m = (m + 255) >> 8;
        }
    }
    if (len > 1) {
        uint16_t R2[(len + 1) / 2];
        uint16_t M2[(len + 1) / 2];
        ssize_t i;
        for (i = 0; i < len - 1; i += 2) {
            uint32_t m0 = M[i];
            uint32_t r = R[i] + R[i + 1] * m0;
            uint32_t m = M[i + 1] * m0;
            while (m >= 16384) {
                *out++ = r;
                r >>= 8;
                m = (m + 255) >> 8;
            }
            R2[i / 2] = r;
            M2[i / 2] = m;
        }
        if (i < len) {
            R2[i / 2] = R[i];
            M2[i / 2] = M[i];
        }
        Encode(out, R2, M2, (len + 1) / 2);
    }
}

/* kem.c */

/* ----- arithmetic mod 3 */

typedef int8_t small;

/* F3 is always represented as -1,0,1 */
/* so ZZ_fromF3 is a no-op */

/* works for -16384 <= x < 16384 */
static small F3_freeze(int16_t x) {
    return (int8_t) (x - 3 * ((10923 * x + 16384) >> 15));
}

//x^19 + x^18 + 2*x^16 + x^15 + x^14 + x^13 + x^12 + 2*x^11 + 2*x^9 + x^8 +
//        2*x^7 + x^6 + 2*x^5 + 2*x^4 + 2*x^3 + 2*x + 2,
static const uint8_t fac0[20] = { 2, 2, 0, 2, 2, 2, 1, 2, 1, 2, 0, 2, 1, 1, 1, 1, 2, 0, 1, 1 };

static const uint8_t fac1[61] = {
1, 2, 1, 1,  0, 0, 1, 2,  0, 2, 0, 2,  0, 1, 1, 1,  1, 1, 0, 0,  2, 0, 1, 1,  0, 0, 1, 0,  1, 0, 0, 2,
2, 1, 1, 2,  0, 1, 1, 0,  0, 1, 1, 2,  0, 0, 1, 1,  1, 1, 2, 0,  0, 1, 2, 0,  2, 2, 1, 0,  1 };

static const uint8_t fac2[683] = {
1, 1, 0, 0, 2, 1, 1, 1, 0, 1, 2, 0, 2, 1, 0, 0, 0, 1, 1, 1, 2, 2, 1, 0, 1, 0, 1, 1, 0, 2, 1, 0, 2, 0, 2,
1, 0, 0, 2, 1, 0, 1, 2, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 2, 2, 2, 0, 1, 1, 0, 1, 0, 0, 0, 1, 2, 0, 2, 2, 1,
0, 2, 1, 2, 2, 0, 2, 0, 2, 1, 2, 0, 1, 0, 0, 1, 2, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 2, 0, 0, 0, 1, 1, 1, 2,
2, 2, 0, 0, 2, 0, 1, 2, 2, 1, 2, 1, 1, 0, 2, 2, 1, 2, 0, 0, 1, 2, 1, 2, 1, 2, 0, 1, 1, 2, 1, 0, 0, 0, 2,
1, 0, 0, 1, 1, 0, 0, 0, 0, 2, 0, 2, 1, 0, 1, 1, 2, 0, 1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 1, 0, 1, 2, 0, 1, 1,
1, 2, 0, 1, 0, 1, 2, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 1, 1, 0, 2, 1, 1, 0, 1, 0, 0, 2, 0, 1, 1, 0, 0, 0, 0,
1, 2, 2, 0, 2, 2, 1, 2, 0, 0, 0, 2, 0, 0, 1, 2, 2, 2, 1, 2, 2, 0, 1, 0, 2, 1, 1, 2, 2, 0, 0, 0, 2, 2, 0,
2, 1, 2, 2, 1, 1, 2, 0, 2, 0, 0, 2, 2, 0, 0, 1, 0, 2, 0, 2, 2, 0, 0, 0, 0, 1, 2, 0, 1, 1, 0, 2, 2, 1, 0,
1, 2, 2, 2, 2, 1, 0, 1, 0, 0, 0, 1, 2, 0, 2, 2, 0, 2, 2, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 2, 0,
0, 2, 0, 1, 2, 1, 0, 1, 2, 2, 2, 1, 1, 2, 1, 1, 2, 1, 2, 2, 1, 0, 0, 0, 0, 1, 0, 2, 0, 1, 0, 2, 0, 0, 2,
0, 0, 1, 1, 2, 0, 1, 1, 2, 0, 2, 0, 2, 1, 2, 2, 2, 1, 2, 2, 0, 0, 1, 2, 1, 0, 1, 2, 0, 0, 1, 0, 2, 2, 0,
0, 2, 1, 1, 2, 2, 1, 0, 1, 0, 2, 2, 0, 0, 1, 1, 1, 1, 0, 2, 1, 1, 2, 2, 2, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1,
1, 0, 1, 1, 1, 2, 2, 0, 1, 1, 0, 0, 2, 2, 2, 1, 0, 0, 2, 0, 2, 1, 0, 0, 1, 0, 2, 2, 0, 0, 2, 1, 0, 2, 1,
0, 1, 1, 2, 1, 1, 2, 1, 1, 0, 0, 2, 1, 2, 0, 0, 0, 2, 2, 0, 0, 0, 1, 0, 0, 2, 0, 1, 2, 1, 1, 2, 0, 1, 1,
1, 1, 2, 2, 2, 2, 0, 0, 2, 1, 1, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 2, 1, 1, 2, 1, 0, 2, 0, 1, 1, 1, 1, 0, 1,
0, 1, 1, 2, 1, 1, 2, 2, 0, 1, 2, 0, 1, 1, 0, 0, 1, 1, 0, 2, 2, 0, 2, 2, 2, 1, 2, 2, 2, 1, 1, 1, 0, 1, 1,
1, 0, 2, 2, 1, 1, 1, 1, 1, 0, 0, 1, 1, 2, 2, 2, 2, 2, 0, 0, 0, 1, 1, 2, 1, 1, 0, 1, 1, 2, 1, 0, 1, 0, 2,
1, 1, 1, 1, 0, 1, 0, 1, 1, 2, 0, 0, 2, 0, 0, 0, 2, 1, 1, 0, 0, 0, 0, 2, 0, 1, 1, 2, 0, 2, 0, 2, 2, 1, 0,
1, 1, 0, 1, 2, 0, 2, 1, 1, 2, 2, 0, 2, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 0, 2, 2, 2, 2, 2, 1, 2, 2, 2, 1, 1,
1, 1, 2, 2, 2, 2, 0, 0, 1, 0, 2, 1, 0, 1, 2, 0, 2, 1
};

static void mulsub3(uint8_t * a, uint8_t m, const uint8_t * b, unsigned len_b)
{
  for(unsigned i=0;i<len_b;i++) {
    a[i] += 6 - m*b[i];
    char fz = F3_freeze(a[i]); // 1,0,-1
    fz += ((fz>>2)&0x3);  // 1,0,2
    a[i] = (uint8_t)fz;
  }
}

static void mod3(uint8_t * dividend, unsigned len_dividen, const uint8_t *divisor, unsigned len_divisor)
{
  for(int i=len_dividen-len_divisor;i>=0;i--){
    mulsub3(dividend+i, dividend[i+len_divisor-1], divisor, len_divisor);
  }
}

static void mod3_fac0(uint8_t * poly)
{
  mod3(poly, p, fac0, sizeof(fac0));
}

static void mod3_fac1(uint8_t * poly)
{
  mod3(poly, p, fac1, sizeof(fac1));
}

static void mod3_fac2(uint8_t * poly)
{
  mod3(poly, p, fac2, sizeof(fac2));
}

static uint8_t is_zero(const uint8_t * v, int len)
{
  uint8_t r = 0;
  for(int i=0;i<len;i++) r |= v[i];

  unsigned rr = r;
  rr -= 1;  // 0->-1, else ->   0 <= v < 254
  rr >>= 8;
  return (rr&1);
}

/* byte 0 of output is 1 if input is 0 on GF(3)[x]/x^p-x-1; else 0 */
static int crypto_core_iszeromod3(uint8_t *outbytes, const uint8_t *inbytes)
{
  uint8_t mm[p];
  // only use lsb 2 bits
  // 00->0, 01->1, 10->0, 11->2
  for(int i=0;i<p;i++) {
    char fi = (char)inbytes[i];
    char fi0 = fi&1;
    fi = fi0-(fi&(fi0<<1)); // 1,0,or -1
    fi += ((fi>>2)&0x3);  // 1,0,2
    mm[i] = (uint8_t)fi;
  }

  uint8_t r = 0;
  uint8_t mm2[p];
  memcpy(mm2,mm,p);
  mod3_fac0(mm2);
  r |= is_zero(mm2, sizeof(fac0)-1);

  memcpy(mm2,mm,p);
  mod3_fac1(mm2);
  r |= is_zero(mm2, sizeof(fac1)-1);

  mod3_fac2(mm);
  r |= is_zero(mm, sizeof(fac2)-1);

  outbytes[0] = r;

  return 0;
}


/* ----- arithmetic mod q */

#define q12 ((q - 1) / 2)
typedef int16_t Fq;
/* always represented as -q12...q12 */
/* so ZZ_fromFq is a no-op */

typedef struct {
  int16_t lane[16];
} int16x16;


/* works for -7000000 < x < 7000000 if q in 4591, 4621, 5167, 6343, 7177, 7879 */
static Fq Fq_freeze(int32_t x) {
    x -= q * ((q18 * x) >> 18);
    x -= q * ((q27 * x + 67108864) >> 27);
    return (Fq) x;
}


static Fq Fq_recip(Fq a1) {
    int i = 1;
    Fq ai = a1;

    while (i < q - 2) {
        ai = Fq_freeze(a1 * (int32_t) ai);
        i += 1;
    }
    return ai;
}

/* ----- int8_t polynomials */

static void crypto_decode_pxint16(void *v, const uint8_t *s)
{
    uint16_t *x = v;
    int i;

    for (i = 0; i < 761; ++i) {
        uint16_t u0 = s[0];
        uint16_t u1 = s[1];
        *x = (uint16_t) (u0 | (u1 << 8));
        x += 1;
        s += 2;
    }
}

static void crypto_decode_pxint32(void *v, const uint8_t *s) {
    uint32_t *x = v;
    int i;

    for (i = 0; i < 761; ++i) {
        uint32_t u0 = s[0];
        uint32_t u1 = s[1];
        uint32_t u2 = s[2];
        uint32_t u3 = s[3];
        u1 <<= 8;
        u2 <<= 16;
        u3 <<= 24;
        *x = u0 | u1 | u2 | u3;
        x += 1;
        s += 4;
    }
}

static void crypto_encode_pxint16(uint8_t *s, const void *v) {
    const uint16_t *x = v;
    int i;

    for (i = 0; i < 761; ++i) {
        uint16_t u = *x++;
        *s++ = (uint8_t) u;
        *s++ = (uint8_t) (u >> 8);
    }
}

static int crypto_core_inv3(uint8_t *outbytes, const uint8_t *inbytes) {
    int8_t *out = (void *) outbytes;
    int8_t *in = (void *) inbytes;
    int8_t f[p + 1], g[p + 1], v[p + 1], r[p + 1];
    int i, loop, delta;
    int sign, swap, t;

    for (i = 0; i < p + 1; ++i) {
        v[i] = 0;
    }
    for (i = 0; i < p + 1; ++i) {
        r[i] = 0;
    }
    r[0] = 1;
    for (i = 0; i < p; ++i) {
        f[i] = 0;
    }
    f[0] = 1;
    f[p - 1] = f[p] = -1;
    for (i = 0; i < p; ++i) {
        int8_t i1 = in[i] & 1;
        g[p - 1 - i] = (int8_t) (i1 - (in[i] & (i1 << 1)));
    }
    g[p] = 0;

    delta = 1;

    for (loop = 0; loop < 2 * p - 1; ++loop) {
        for (i = p; i > 0; --i) {
            v[i] = v[i - 1];
        }
        v[0] = 0;

        sign = -g[0] * f[0];
        swap = crypto_int16_negative_mask((int16_t) - delta) & crypto_int16_nonzero_mask(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for (i = 0; i < p + 1; ++i) {
            t = swap & (f[i] ^ g[i]);
            f[i] ^= (int8_t) t;
            g[i] ^= (int8_t) t;
            t = swap & (v[i] ^ r[i]);
            v[i] ^= (int8_t) t;
            r[i] ^= (int8_t) t;
        }

        for (i = 0; i < p + 1; ++i) {
            g[i] = F3_freeze((int16_t) (g[i] + sign * f[i]));
        }
        for (i = 0; i < p + 1; ++i) {
            r[i] = F3_freeze((int16_t) (r[i] + sign * v[i]));
        }

        for (i = 0; i < p; ++i) {
            g[i] = g[i + 1];
        }
        g[p] = (int16_t) 0;
    }

    sign = (int) f[0];
    for (i = 0; i < p; ++i) {
        out[i] = (int8_t) (sign * v[p - 1 - i]);
    }

    out[p] = (int8_t) crypto_int16_nonzero_mask((int16_t) delta);
    return 0;
}

/* out = 3*in in Rq */
static int crypto_core_scale3(uint8_t *outbytes, const uint8_t *inbytes) {
    Fq f[p];
    int i;

    crypto_decode_pxint16(f, inbytes);
    for (i = 0; i < p; ++i) {
        Fq x = f[i];
        x *= 3; /* (-3q+3)/2 ... (3q-3)/2 */
        x -= (q + 1) / 2; /* -2q+1 ... q-2 */
        x += q & (x >> 15); /* -q+1 ... q-1 */
        x += q & (x >> 15); /* 0 ... q-1 */
        x -= (q - 1) / 2; /* -(q-1)/2 ... (q-1)/2 */
        f[i] = x;
    }
    crypto_encode_pxint16(outbytes, f);

    return 0;
}

static int crypto_core_mult(uint8_t *outbytes, const uint8_t *inbytes, const uint8_t *kbytes) {
    Fq f[p];
    int8_t g[p];
    Fq fg[p + p - 1];
    int32_t result;
    int i, j;

    crypto_decode_pxint16(f, inbytes);
    for (i = 0; i < p; ++i) {
        f[i] = Fq_freeze(f[i]);
    }

    for (i = 0; i < p; ++i) {
        small gi = (int8_t) kbytes[i];
        small gi0 = gi & 1;
        g[i] = (int8_t) (gi0 - (gi & (gi0 << 1)));
    }

    for (i = 0; i < p; ++i) {
        result = 0;
        for (j = 0; j <= i; ++j) {
            result += f[j] * (int32_t)g[i - j];
        }
        fg[i] = Fq_freeze(result);
    }
    for (i = p; i < p + p - 1; ++i) {
        result = 0;
        for (j = i - p + 1; j < p; ++j) {
            result += f[j] * (int32_t)g[i - j];
        }
        fg[i] = Fq_freeze(result);
    }

    for (i = p + p - 2; i >= p; --i) {
        fg[i - p] = Fq_freeze(fg[i - p] + fg[i]);
        fg[i - p + 1] = Fq_freeze(fg[i - p + 1] + fg[i]);
    }

    crypto_encode_pxint16(outbytes, fg);
    return 0;
}

static inline int16_t mullo(int16_t x,int16_t y)
{
  return x*y;
}

static inline int16_t mulhi(int16_t x,int16_t y)
{
  return (x*(int32_t)y)>>16;
}

static inline int16_t mulhrs(int16_t x,int16_t y)
{
  return (x*(int32_t)y+16384)>>15;
}

/* input range: -2^15 <= x < 2^15 */
/* output range: -4000 < out < 4000 */
static inline int16_t squeeze13(int16_t x)
{
  /* XXX: for q=5167, need to do mulhi+mulhrs+mullo to achieve this range */
  x = x - mullo(mulhrs(x,q15),q);
  return x;
}

/* input range: -2^15 <= x < 2^15 */
/* output range: -8000 < out < 8000 */
static inline int16_t squeeze14(int16_t x)
{
  x = x - mullo(mulhrs(x,q15),q);
  return x;
}

static int16x16 add_x16(int16x16 f,int16x16 g)
{
  int i;
  int16x16 result;

  for (i = 0;i < 16;++i)
    result.lane[i] = f.lane[i] + g.lane[i];
  return result;
}

static int16x16 neg_x16(int16x16 f)
{
  int i;
  int16x16 result;

  for (i = 0;i < 16;++i)
    result.lane[i] = -f.lane[i];
  return result;
}

static int16x16 sub_x16(int16x16 f,int16x16 g)
{
  int i;
  int16x16 result;

  for (i = 0;i < 16;++i)
    result.lane[i] = f.lane[i] - g.lane[i];
  return result;
}

static int16x16 squeeze13_x16(int16x16 f)
{
  int i;
  int16x16 result;

  for (i = 0;i < 16;++i)
    result.lane[i] = squeeze13(f.lane[i]);
  return result;
}

static int16x16 squeeze14_x16(int16x16 f)
{
  int i;
  int16x16 result;

  for (i = 0;i < 16;++i)
    result.lane[i] = squeeze14(f.lane[i]);
  return result;
}

/* h = fg/65536 in (k^16)[x] */
/* where f,g are 1-coeff polys */
/* input range: +-16000 */
/* output range: +-8000 */
static void mult1_over65536_x16(int16x16 h[1],const int16x16 f[1],const int16x16 g[1])
{
  /* 4 mul + 1 add */
  int i;

  for (i = 0;i < 16;++i) {
    int16_t fp = f[0].lane[i];
    int16_t gp = g[0].lane[i];
    int16_t gpqinv = mullo(gp,qinv);
    int16_t b = mulhi(fp,gp);
    int16_t d = mullo(fp,gpqinv);
    int16_t e = mulhi(d,q);
    int16_t hp = b - e;
    h[0].lane[i] = hp;
  }
}

/* h = fg/65536 in (k^16)[x] */
/* where f,g are 2-coeff polys */
/* input range: +-8000 */
/* output range: +-8000 */
static void mult2_over65536_x16(int16x16 h[3],const int16x16 f[2],const int16x16 g[2])
{
  /* strategy: refined Karatsuba */
  /* 14 mul + 8 add */
  /* XXX: can replace mullo(g01p,qinv) with an add */
  /* XXX: similarly at higher levels */

  int16x16 f01[1];
  int16x16 g01[1];

  f01[0] = add_x16(f[0],f[1]);
  g01[0] = add_x16(g[0],g[1]);

  mult1_over65536_x16(h,f,g);
  mult1_over65536_x16(h+2,f+1,g+1);
  mult1_over65536_x16(h+1,f01,g01);

  h[1] = squeeze14_x16(sub_x16(h[1],add_x16(h[0],h[2])));
}

/* h = fg/65536 in (k^16)[x] */
/* where f,g are 4-coeff polys */
/* input range: +-4000 */
/* output range: +-8000 */
static void mult4_over65536_x16(int16x16 h[7],const int16x16 f[4],const int16x16 g[4])
{
  /* strategy: refined Karatsuba */
  /* 48 mul + 38 add */

  int16x16 f01[2];
  int16x16 g01[2];
  int16x16 h01[3];
  int16x16 c;

  f01[0] = add_x16(f[0],f[2]);
  f01[1] = add_x16(f[1],f[3]);
  g01[0] = add_x16(g[0],g[2]);
  g01[1] = add_x16(g[1],g[3]);

  mult2_over65536_x16(h,f,g);
  mult2_over65536_x16(h+4,f+2,g+2);
  mult2_over65536_x16(h01,f01,g01);

  c = sub_x16(h[2],h[4]);
  h[2] = squeeze14_x16(add_x16(sub_x16(h01[0],h[0]),c));
  h[3] = squeeze14_x16(sub_x16(h01[1],add_x16(h[1],h[5])));
  h[4] = squeeze14_x16(sub_x16(sub_x16(h01[2],h[6]),c));
}

/* h = fg/65536 in (k^16)[x]/(x^8+1) */
/* input range: +-4000 */
/* output range: +-4000 */
static void mult8_nega_over65536_x16(int16x16 h[8],const int16x16 f[8],const int16x16 g[8])
{
  /* strategy: reduced refined Karatsuba */
  /* 176 mul + 159 add */

  int16x16 f01[4],g01[4],h01[7],htop[7],c0,c1,c2,d0,d1,d2;

  f01[0] = squeeze13_x16(add_x16(f[0],f[4]));
  f01[1] = squeeze13_x16(add_x16(f[1],f[5]));
  f01[2] = squeeze13_x16(add_x16(f[2],f[6]));
  f01[3] = squeeze13_x16(add_x16(f[3],f[7]));
  g01[0] = squeeze13_x16(add_x16(g[0],g[4]));
  g01[1] = squeeze13_x16(add_x16(g[1],g[5]));
  g01[2] = squeeze13_x16(add_x16(g[2],g[6]));
  g01[3] = squeeze13_x16(add_x16(g[3],g[7]));

  mult4_over65536_x16(h,f,g);
  mult4_over65536_x16(htop,f+4,g+4);
  mult4_over65536_x16(h01,f01,g01);

  c0 = sub_x16(h[4],htop[0]);
  c1 = sub_x16(h[5],htop[1]);
  c2 = sub_x16(h[6],htop[2]);
  d0 = add_x16(h[0],htop[4]);
  d1 = add_x16(h[1],htop[5]);
  d2 = add_x16(h[2],htop[6]);

  h[7] = squeeze13_x16(sub_x16(h01[3],add_x16(h[3],htop[3])));
  h[3] = squeeze13_x16(sub_x16(h[3],htop[3]));

  h[0] = squeeze13_x16(add_x16(sub_x16(c0,h01[4]),d0));
  h[1] = squeeze13_x16(add_x16(sub_x16(c1,h01[5]),d1));
  h[2] = squeeze13_x16(add_x16(sub_x16(c2,h01[6]),d2));
  h[4] = squeeze13_x16(sub_x16(add_x16(c0,h01[0]),d0));
  h[5] = squeeze13_x16(sub_x16(add_x16(c1,h01[1]),d1));
  h[6] = squeeze13_x16(sub_x16(add_x16(c2,h01[2]),d2));
}

/* multiply f by x in (k^16)[x]/(x^8+1) */
static void twist8_1(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = neg_x16(f7);
  f[1] = f0;
  f[2] = f1;
  f[3] = f2;
  f[4] = f3;
  f[5] = f4;
  f[6] = f5;
  f[7] = f6;
}

/* multiply f by x^2 in (k^16)[x]/(x^8+1) */
static void twist8_2(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = neg_x16(f6);
  f[1] = neg_x16(f7);
  f[2] = f0;
  f[3] = f1;
  f[4] = f2;
  f[5] = f3;
  f[6] = f4;
  f[7] = f5;
}

/* multiply f by x^3 in (k^16)[x]/(x^8+1) */
static void twist8_3(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = neg_x16(f5);
  f[1] = neg_x16(f6);
  f[2] = neg_x16(f7);
  f[3] = f0;
  f[4] = f1;
  f[5] = f2;
  f[6] = f3;
  f[7] = f4;
}

/* multiply f by x^4 in (k^16)[x]/(x^8+1) */
static void twist8_4(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = neg_x16(f4);
  f[1] = neg_x16(f5);
  f[2] = neg_x16(f6);
  f[3] = neg_x16(f7);
  f[4] = f0;
  f[5] = f1;
  f[6] = f2;
  f[7] = f3;
}

/* multiply f by x^6 in (k^16)[x]/(x^8+1) */
static void twist8_6(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = neg_x16(f2);
  f[1] = neg_x16(f3);
  f[2] = neg_x16(f4);
  f[3] = neg_x16(f5);
  f[4] = neg_x16(f6);
  f[5] = neg_x16(f7);
  f[6] = f0;
  f[7] = f1;
}

/* multiply f by x^10 in (k^16)[x]/(x^8+1) */
static void twist8_10(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = f6;
  f[1] = f7;
  f[2] = neg_x16(f0);
  f[3] = neg_x16(f1);
  f[4] = neg_x16(f2);
  f[5] = neg_x16(f3);
  f[6] = neg_x16(f4);
  f[7] = neg_x16(f5);
}

/* multiply f by x^12 in (k^16)[x]/(x^8+1) */
static void twist8_12(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = f4;
  f[1] = f5;
  f[2] = f6;
  f[3] = f7;
  f[4] = neg_x16(f0);
  f[5] = neg_x16(f1);
  f[6] = neg_x16(f2);
  f[7] = neg_x16(f3);
}

/* multiply f by x^13 in (k^16)[x]/(x^8+1) */
static void twist8_13(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = f3;
  f[1] = f4;
  f[2] = f5;
  f[3] = f6;
  f[4] = f7;
  f[5] = neg_x16(f0);
  f[6] = neg_x16(f1);
  f[7] = neg_x16(f2);
}

/* multiply f by x^14 in (k^16)[x]/(x^8+1) */
static void twist8_14(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = f2;
  f[1] = f3;
  f[2] = f4;
  f[3] = f5;
  f[4] = f6;
  f[5] = f7;
  f[6] = neg_x16(f0);
  f[7] = neg_x16(f1);
}

/* multiply f by x^15 in (k^16)[x]/(x^8+1) */
static void twist8_15(int16x16 f[8])
{
  int16x16 f0 = f[0];
  int16x16 f1 = f[1];
  int16x16 f2 = f[2];
  int16x16 f3 = f[3];
  int16x16 f4 = f[4];
  int16x16 f5 = f[5];
  int16x16 f6 = f[6];
  int16x16 f7 = f[7];
  f[0] = f1;
  f[1] = f2;
  f[2] = f3;
  f[3] = f4;
  f[4] = f5;
  f[5] = f6;
  f[6] = f7;
  f[7] = neg_x16(f0);
}

/* input range: +-4000 */
/* output range: +-4000 */
static void fft64(int16x16 fpad[16][8],const int16x16 f[64])
{
  /* 256 mul + 512 add + some negations */

  int i,j;

  /* stage 1: y^16-1 -> y^8-1, y^8+1 */
  /* integrated with initial lift */
  /* XXX: integrate more */

  for (i = 0;i < 8;++i)
    for (j = 0;j < 8;++j)
      fpad[i+8][j] = fpad[i][j] = f[i+8*j];

  /* stage 2a: y^8-1 -> y^4-1, y^4+1 */

  for (i = 0;i < 4;++i)
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+4][j];

      /* a y^i x^j + A y^(i+4) x^j */
      /* -> (a+A) y^i x^j, (a-A) y^i x^j */

      fpad[i][j] = add_x16(a,A);
      fpad[i+4][j] = sub_x16(a,A);
    }

  /* stage 2b: y^8+1 -> y^4-x^4, y^4+x^4 */

  for (i = 8;i < 12;++i)
    for (j = 0;j < 4;++j) {
      int16x16 a = fpad[i][j];
      int16x16 b = fpad[i][j+4];
      int16x16 A = fpad[i+4][j];
      int16x16 B = fpad[i+4][j+4];

      /* a y^i x^j + b y^i x^(j+4) + A y^(i+4) x^j + B y^(i+4) x^(j+4) */
      /* -> (a-B) y^i x^j + (b+A) y^i x^(j+4), */
      /*    (a+B) y^i x^j + (b-A) y^i x^(j+4) */

      fpad[i][j] = sub_x16(a,B);
      fpad[i][j+4] = add_x16(b,A);
      fpad[i+4][j] = add_x16(a,B);
      fpad[i+4][j+4] = sub_x16(b,A);
    }

  /* twist y^4-1,y^4+1,y^4-x^4,y^4+x^4 -> z^4-1,z^4-1,z^4-1,z^4-1: */
  /* 1,y,y^2,y^3,1,y,y^2,y^3,1,y,y^2,y^3,1,y,y^2,y^3 */
  /* -> 1,z,z^2,z^3,1,zx^2,z^2x^4,z^3x^6,1,zx,z^2x^2,z^3x^3,1,z/x,z^2/x^2,z^3/x^3 */

  twist8_2(fpad[5]);
  twist8_4(fpad[6]);
  twist8_6(fpad[7]);
  twist8_1(fpad[9]);
  twist8_2(fpad[10]);
  twist8_3(fpad[11]);
  twist8_15(fpad[13]);
  twist8_14(fpad[14]);
  twist8_13(fpad[15]);

  /* rename z as y: y^4-1,y^4-1,y^4-1,y^4-1 */

  /* stage 3: y^4-1 -> y^2-1,y^2+1 */

  for (i = 0;i < 16;++i) if (!(i & 2))
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+2][j];
      fpad[i][j] = add_x16(a,A);
      fpad[i+2][j] = sub_x16(a,A);
    }

  /* stage 4a: y^2-1 -> y-1, y+1 */

  for (i = 0;i < 16;i += 4)
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+1][j];
      fpad[i][j] = add_x16(a,A);
      fpad[i+1][j] = sub_x16(a,A);
    }

  /* stage 4b: y^2+1 -> y-x^4, y+x^4 */

  for (i = 2;i < 16;i += 4)
    for (j = 0;j < 4;++j) {
      int16x16 a = fpad[i][j];
      int16x16 b = fpad[i][j+4];
      int16x16 A = fpad[i+1][j];
      int16x16 B = fpad[i+1][j+4];

      fpad[i][j] = sub_x16(a,B);
      fpad[i][j+4] = add_x16(b,A);
      fpad[i+1][j] = add_x16(a,B);
      fpad[i+1][j+4] = sub_x16(b,A);
    }

  for (i = 0;i < 16;++i)
    for (j = 0;j < 8;++j)
      fpad[i][j] = squeeze13_x16(fpad[i][j]);
}

/* inverse of fft64 except for a multiplication by 16 */
static void unfft64_scale16(int16x16 f[64],int16x16 fpad[16][8])
{
  int i,j;

  /* undo stage 4 */

  for (i = 0;i < 16;i += 4)
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+1][j];
      fpad[i][j] = add_x16(a,A);
      fpad[i+1][j] = sub_x16(a,A);
    }

  for (i = 2;i < 16;i += 4)
    for (j = 0;j < 4;++j) {
      int16x16 a = fpad[i][j];
      int16x16 b = fpad[i][j+4];
      int16x16 A = fpad[i+1][j];
      int16x16 B = fpad[i+1][j+4];

      fpad[i][j] = add_x16(A,a);
      fpad[i][j+4] = add_x16(b,B);
      fpad[i+1][j] = sub_x16(b,B);
      fpad[i+1][j+4] = sub_x16(A,a);
    }

  /* undo stage 3 */

  for (i = 0;i < 16;++i) if (!(i & 2))
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+2][j];
      fpad[i][j] = add_x16(a,A);
      fpad[i+2][j] = sub_x16(a,A);
    }

  /* undo twists */

  twist8_14(fpad[5]);
  twist8_12(fpad[6]);
  twist8_10(fpad[7]);
  twist8_15(fpad[9]);
  twist8_14(fpad[10]);
  twist8_13(fpad[11]);
  twist8_1(fpad[13]);
  twist8_2(fpad[14]);
  twist8_3(fpad[15]);

  for (i = 0;i < 16;++i)
    for (j = 0;j < 8;++j)
      fpad[i][j] = squeeze13_x16(fpad[i][j]);

  /* undo stage 2 */

  for (i = 0;i < 4;++i)
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+4][j];

      fpad[i][j] = add_x16(a,A);
      fpad[i+4][j] = sub_x16(a,A);
    }

  for (i = 8;i < 12;++i)
    for (j = 0;j < 4;++j) {
      int16x16 a = fpad[i][j];
      int16x16 b = fpad[i][j+4];
      int16x16 A = fpad[i+4][j];
      int16x16 B = fpad[i+4][j+4];

      fpad[i][j] = add_x16(A,a);
      fpad[i][j+4] = add_x16(b,B);
      fpad[i+4][j] = sub_x16(b,B);
      fpad[i+4][j+4] = sub_x16(A,a);
    }

  /* undo stage 1 */

  for (i = 0;i < 7;++i)
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      int16x16 A = fpad[i+8][j];

      fpad[i][j] = add_x16(a,A);
      fpad[i+8][j] = sub_x16(a,A);
    }
  for (i = 7;i < 8;++i)
    for (j = 0;j < 8;++j) {
      int16x16 a = fpad[i][j];
      fpad[i][j] = add_x16(a,a);
      /* fpad[i+8][j] = 0; */ /* unused below */
    }

  /* map to (k[x]/(x^8+1))[y]/(y^8-x) */

  for (i = 0;i < 7;++i) {
    f[i] = squeeze13_x16(sub_x16(fpad[i][0],fpad[i+8][7]));
    for (j = 1;j < 8;++j)
      f[i+8*j] = squeeze13_x16(add_x16(fpad[i][j],fpad[i+8][j-1]));
  }
  for (i = 7;i < 8;++i) {
    /* y^15 does not appear; i.e., fpad[i+8] is 0 */
    for (j = 0;j < 8;++j)
      f[i+8*j] = squeeze13_x16(fpad[i][j]);
  }
}

/* h = fg/4096 in (k^16)[y]/(y^64+1) */
/* input range: +-4000 */
/* output range: +-4000 */
static void mult64_nega_over4096_x16(int16x16 h[64],const int16x16 f[64],const int16x16 g[64])
{
  /* strategy: Nussbaumer's trick */
  /* map k[y]/(y^64+1) to (k[x]/(x^8+1))[y]/(y^8-x) */
  /* lift to (k[x]/(x^8+1))[y] */
  /* map to (k[x]/(x^8+1))[y]/(y^16-1) */
  /* then use size-16 FFT, and 16 mults in k[x]/(x^8+1) */

  int16x16 fpad[16][8];
  int16x16 gpad[16][8];
  int16x16 hpad[16][8]; /* XXX: overlap fpad */
  int i;

  fft64(fpad,f);
  fft64(gpad,g);

  for (i = 0;i < 16;++i)
    mult8_nega_over65536_x16(hpad[i],fpad[i],gpad[i]);

  unfft64_scale16(h,hpad);
}

/* input in (k[x]/(x^64+1))[y]/(y^8-1) */
/* f represents poly: sum f[i][j] y^i x^j */
/* output (in place): 8 elements of k[x]/(x^64+1) */
/* input range: +-4000 */
/* output range: +-4000 */
static void fft8_64(int16_t f[8][64])
{
  int i,j;

  /* stage 1: y^8-1 -> y^4-1, y^4+1 */
  for (i = 0;i < 4;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+4][j];
      f[i][j] = a + A;
      f[i+4][j] = a - A;
    }

  /* stage 2: y^2-1, y^2+1, y^2-x^32, y^2+x^32 */
  for (i = 0;i < 2;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+2][j];
      f[i][j] = a + A;
      f[i+2][j] = a - A;
    }
  for (i = 4;i < 6;++i)
    for (j = 0;j < 32;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+32];
      int16_t A = f[i+2][j];
      int16_t B = f[i+2][j+32];
      f[i][j] = a - B;
      f[i][j+32] = b + A;
      f[i+2][j] = a + B;
      f[i+2][j+32] = b - A;
    }

  /* stage 3: y-1,y+1,y-x^32,y+x^32,y-x^16,y+x^16,y-x^48,y+x^48 */
  for (i = 0;i < 1;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+1][j];
      f[i][j] = a + A;
      f[i+1][j] = a - A;
    }
  for (i = 2;i < 3;++i)
    for (j = 0;j < 32;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+32];
      int16_t A = f[i+1][j];
      int16_t B = f[i+1][j+32];
      f[i][j] = a - B;
      f[i][j+32] = b + A;
      f[i+1][j] = a + B;
      f[i+1][j+32] = b - A;
    }
  for (i = 4;i < 5;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+1][j];
      int16_t B = f[i+1][j+16];
      int16_t C = f[i+1][j+32];
      int16_t D = f[i+1][j+48];
      f[i][j] = a - D;
      f[i][j+16] = b + A;
      f[i][j+32] = c + B;
      f[i][j+48] = d + C;
      f[i+1][j] = a + D;
      f[i+1][j+16] = b - A;
      f[i+1][j+32] = c - B;
      f[i+1][j+48] = d - C;
    }
  for (i = 6;i < 7;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+1][j];
      int16_t B = f[i+1][j+16];
      int16_t C = f[i+1][j+32];
      int16_t D = f[i+1][j+48];
      f[i][j] = a - B;
      f[i][j+16] = b - C;
      f[i][j+32] = c - D;
      f[i][j+48] = d + A;
      f[i+1][j] = a + B;
      f[i+1][j+16] = b + C;
      f[i+1][j+32] = c + D;
      f[i+1][j+48] = d - A;
    }

  for (i = 0;i < 8;++i)
    for (j = 0;j < 64;++j)
      f[i][j] = squeeze13(f[i][j]);
}

/* input range: +-4000 */
/* output range: +-32000 */
static void unfft8_64_scale8(int16_t f[8][64])
{
  int i,j;

  /* undo stage 3: y-1,y+1,y-x^32,y+x^32,y-x^16,y+x^16,y-x^48,y+x^48 */
  for (i = 0;i < 1;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+1][j];
      f[i][j] = a + A;
      f[i+1][j] = a - A;
    }
  for (i = 2;i < 3;++i)
    for (j = 0;j < 32;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+32];
      int16_t A = f[i+1][j];
      int16_t B = f[i+1][j+32];
      f[i][j] = a + A;
      f[i][j+32] = b + B;
      f[i+1][j] = b - B;
      f[i+1][j+32] = A - a;
    }
  for (i = 4;i < 5;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+1][j];
      int16_t B = f[i+1][j+16];
      int16_t C = f[i+1][j+32];
      int16_t D = f[i+1][j+48];
      f[i][j] = a + A;
      f[i][j+16] = b + B;
      f[i][j+32] = c + C;
      f[i][j+48] = d + D;
      f[i+1][j] = b - B;
      f[i+1][j+16] = c - C;
      f[i+1][j+32] = d - D;
      f[i+1][j+48] = A - a;
    }
  for (i = 6;i < 7;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+1][j];
      int16_t B = f[i+1][j+16];
      int16_t C = f[i+1][j+32];
      int16_t D = f[i+1][j+48];
      f[i][j] = a + A;
      f[i][j+16] = b + B;
      f[i][j+32] = c + C;
      f[i][j+48] = d + D;
      f[i+1][j] = d - D;
      f[i+1][j+16] = A - a;
      f[i+1][j+32] = B - b;
      f[i+1][j+48] = C - c;
    }

  /* undo stage 2: y^2-1, y^2+1, y^2-x^32, y^2+x^32 */
  for (i = 0;i < 2;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+2][j];
      f[i][j] = a + A;
      f[i+2][j] = a - A;
    }
  for (i = 4;i < 6;++i)
    for (j = 0;j < 32;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+32];
      int16_t A = f[i+2][j];
      int16_t B = f[i+2][j+32];
      f[i][j] = a + A;
      f[i][j+32] = b + B;
      f[i+2][j] = b - B;
      f[i+2][j+32] = A - a;
    }

  /* undo stage 1: y^4-1, y^4+1 */
  for (i = 0;i < 4;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+4][j];
      f[i][j] = a + A;
      f[i+4][j] = a - A;
    }
}

/* input in (k[x]/(x^64+1))[y]/(y^8-x^8t) */
/* output (in place): (k[x]/(x^64+1))[z]/(z^8-1) */
/* mapping y to z x^t */
/* allowed values of t: -8...8 */
static void twist64(int16_t f[8][64],int t)
{
  int16_t fi[64];
  int i,j;

  if (t > 0) {
    for (i = 1;i < 8;++i) {
      for (j = 0;j < 64;++j) fi[j] = f[i][j];
      for (j = 0;j < i*t;++j) f[i][j] = -fi[j+64-i*t];
      for (j = i*t;j < 64;++j) f[i][j] = fi[j-i*t];
    }
  } else {
    t = -t;
    for (i = 1;i < 8;++i) {
      for (j = 0;j < 64;++j) fi[j] = f[i][j];
      for (j = 0;j < i*t;++j) f[i][j+64-i*t] = -fi[j];
      for (j = i*t;j < 64;++j) f[i][j-i*t] = fi[j];
    }
  }
}

/* size-48 truncated FFT over k[x]/(x^64+1) */
/* input in (k[x]/(x^64+1))[y]/(y^48-y^32+y^16-1) */
/* output (in place): 48 elements of k[x]/(x^64+1) */
/* input range: +-8000 */
/* output range: +-4000 */
static void fft48_64(int16_t f[48][64])
{
  int i,j;

  /* XXX: take more advantage of zeros in inputs */

  /* stage 1: y^48-y^32+y^16-1 -> y^32+1, y^16-1 */
  /* exploiting inputs having y-degree <24 */
  /* exploiting inputs having x-degree <32 */

  for (i = 0;i < 8;++i)
    for (j = 0;j < 32;++j) {
      f[i+32][j] = f[i][j] + f[i+16][j];
      f[i+40][j] = f[i+8][j];
    }

  /* stage 2: y^32+1 -> y^16-x^32, y^16+x^32 */

  for (i = 0;i < 16;++i)
    for (j = 0;j < 32;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+16][j];
      /* a + 0 x^32 + A y^16 + 0 y^16 x^32 */
      /* (a-0) + (0+A) x^32, (a+0) + (0-A) x^32 */
      f[i][j] = a;
      f[i][j+32] = A;
      f[i+16][j] = a;
      f[i+16][j+32] = -A;
    }

  /* stage 3: y^8-x^16, y^8+x^16, y^8-x^48, y^8+x^48, y^8-1, y^8+1 */

  for (i = 0;i < 8;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+8][j];
      int16_t B = f[i+8][j+16];
      int16_t C = f[i+8][j+32];
      int16_t D = f[i+8][j+48];
      f[i][j] = a - D;
      f[i][j+16] = b + A;
      f[i][j+32] = c + B;
      f[i][j+48] = d + C;
      f[i+8][j] = a + D;
      f[i+8][j+16] = b - A;
      f[i+8][j+32] = c - B;
      f[i+8][j+48] = d - C;
    }

  for (i = 16;i < 24;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+8][j];
      int16_t B = f[i+8][j+16];
      int16_t C = f[i+8][j+32];
      int16_t D = f[i+8][j+48];
      f[i][j] = a - B;
      f[i][j+16] = b - C;
      f[i][j+32] = c - D;
      f[i][j+48] = d + A;
      f[i+8][j] = a + B;
      f[i+8][j+16] = b + C;
      f[i+8][j+32] = c + D;
      f[i+8][j+48] = d - A;
    }

  for (i = 32;i < 40;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+8][j];
      f[i][j] = a + A;
      f[i+8][j] = a - A;
    }

  twist64(f,2);
  twist64(f+8,-6);
  twist64(f+16,6);
  twist64(f+24,-2);
  twist64(f+40,8);

  for (i = 0;i < 48;++i)
    for (j = 0;j < 64;++j)
      f[i][j] = squeeze13(f[i][j]);

  fft8_64(f);
  fft8_64(f+8);
  fft8_64(f+16);
  fft8_64(f+24);
  fft8_64(f+32);
  fft8_64(f+40);
}

/* input range: +-4000 */
/* output range: +-16000 */
static void unfft48_64_scale64(int16_t f[48][64])
{
  int i, j;

  unfft8_64_scale8(f);
  unfft8_64_scale8(f+8);
  unfft8_64_scale8(f+16);
  unfft8_64_scale8(f+24);
  unfft8_64_scale8(f+32);
  unfft8_64_scale8(f+40);

  twist64(f,-2);
  twist64(f+8,6);
  twist64(f+16,-6);
  twist64(f+24,2);
  twist64(f+40,-8);

  for (i = 0;i < 48;++i)
    for (j = 0;j < 64;++j)
      f[i][j] = squeeze13(f[i][j]);

  /* undo stage 3: y^8-x^16, y^8+x^16, y^8-x^48, y^8+x^48, y^8-1, y^8+1 */

  for (i = 0;i < 8;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+8][j];
      int16_t B = f[i+8][j+16];
      int16_t C = f[i+8][j+32];
      int16_t D = f[i+8][j+48];
      f[i][j] = a + A;
      f[i][j+16] = b + B;
      f[i][j+32] = c + C;
      f[i][j+48] = d + D;
      f[i+8][j] = b - B;
      f[i+8][j+16] = c - C;
      f[i+8][j+32] = d - D;
      f[i+8][j+48] = A - a;
    }

  for (i = 16;i < 24;++i)
    for (j = 0;j < 16;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+16];
      int16_t c = f[i][j+32];
      int16_t d = f[i][j+48];
      int16_t A = f[i+8][j];
      int16_t B = f[i+8][j+16];
      int16_t C = f[i+8][j+32];
      int16_t D = f[i+8][j+48];
      f[i][j] = a + A;
      f[i][j+16] = b + B;
      f[i][j+32] = c + C;
      f[i][j+48] = d + D;
      f[i+8][j] = d - D;
      f[i+8][j+16] = A - a;
      f[i+8][j+32] = B - b;
      f[i+8][j+48] = C - c;
    }

  for (i = 32;i < 40;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t A = f[i+8][j];
      f[i][j] = a + A;
      f[i+8][j] = a - A;
    }

  /* undo stage 2: y^16-x^32, y^16+x^32 */

  for (i = 0;i < 16;++i)
    for (j = 0;j < 32;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i][j+32];
      int16_t A = f[i+16][j];
      int16_t B = f[i+16][j+32];
      f[i][j] = a + A;
      f[i][j+32] = b + B;
      f[i+16][j] = b - B;
      f[i+16][j+32] = A - a;
    }

  for (i = 0;i < 48;++i)
    for (j = 0;j < 64;++j)
      f[i][j] = squeeze13(f[i][j]);

  /* undo stage 1: y^32+1, y^16-1 */
  for (i = 0;i < 16;++i)
    for (j = 0;j < 64;++j) {
      int16_t a = f[i][j];
      int16_t b = f[i+16][j];
      int16_t c = f[i+32][j];
      c = c + c;
      /* reconstruct r + s y^16 + t y^32 */
      /* from a = r - t, b = s, c = r + s + t */
      c = c - b; /* now a = r - t, b = s, c = r + t */
      f[i][j] = a + c; /* 2r */
      f[i+16][j] = b + b; /* 2s */
      f[i+32][j] = c - a; /* 2t */
    }
}

static void transpose(int16x16 out[64],const int16_t in[16][64])
{
  int i,j;
  for (i = 0;i < 16;++i)
    for (j = 0;j < 64;++j)
      out[j].lane[i] = in[i][j];
}

static void untranspose(int16_t out[16][64],const int16x16 in[64])
{
  int i,j;
  for (i = 0;i < 16;++i)
    for (j = 0;j < 64;++j)
      out[i][j] = in[j].lane[i];
}

/* h = fg/64 in k[y] */
/* where f,g are 768-coeff polys */
/* input range: +-4000 */
/* output range: +-4000 */
static void mult768_over64(int16_t h[1535],const int16_t f[768],const int16_t g[768])
{
  /* strategy: truncated cyclic Schoenhage trick */
  /* map k[y]/(y^1536-y^1024+y^512-1) */
  /* to (k[z]/(z^48-z^32+z^16-1))[y]/(y^32-z) */
  /* lift to k[y][z]/(z^48-z^32+z^16-1) */
  /* map to (k[y]/(y^64+1))[z]/(z^48-z^32+z^16-1) */
  /* note that k[y]/(y^64+1) supports size-128 FFT */

  int i,j;
  int16_t fpad[48][64]; /* sum fpad[i][j] z^i y^j */
  int16_t gpad[48][64];
#define hpad fpad
  int16x16 ftr[64];
  int16x16 gtr[64];
  int16x16 htr[64];
  int16_t result[1536];

  for (i = 0;i < 48;++i)
    for (j = 0;j < 64;++j)
      fpad[i][j] = 0;
  for (i = 0;i < 24;++i)
    for (j = 0;j < 32;++j)
      fpad[i][j] = f[i*32+j];

  /* fpad evaluated at z=y^32 is original poly f */

  for (i = 0;i < 48;++i)
    for (j = 0;j < 64;++j)
      gpad[i][j] = 0;
  for (i = 0;i < 24;++i)
    for (j = 0;j < 32;++j)
      gpad[i][j] = g[i*32+j];

  fft48_64(fpad);
  fft48_64(gpad);

  for (i = 0;i < 48;i += 16) {
    transpose(ftr,fpad+i);
    transpose(gtr,gpad+i);
    mult64_nega_over4096_x16(htr,ftr,gtr);
    untranspose(hpad+i,htr);
  }

  unfft48_64_scale64(hpad);

  for (j = 0;j < 1536;++j)
    result[j] = 0;

  for (i = 0;i <= 46;++i)
    for (j = 0;j < 64;++j)
      result[i*32+j] = result[i*32+j] + hpad[i][j];

  for (j = 0;j < 1535;++j)
    h[j] = squeeze13(result[j]);
}

static inline int16_t montproduct( int16_t x , int16_t y )
{
  int16_t lo = mullo( x , y );
  int16_t hi = mulhi( x , y );
  int16_t d = mullo( lo , 15631 );
  int16_t e = mulhi( d , 4591 );
  return hi-e;
}

static int crypto_core_multbig(uint8_t *outbytes, const uint8_t *inbytes, const uint8_t *kbytes)
{
  Fq f[768];
  Fq g[768];
  Fq fg[1536];
  int i;

  crypto_decode_pxint16(f,inbytes);
  for(i=p;i<768;i++) f[i] = 0;

  crypto_decode_pxint16(g,kbytes);
  for(i=p;i<768;i++) g[i] = 0;

  mult768_over64( fg , f , g );

  for (i = p+p-2;i >= p;--i) {
    fg[i-p] = (fg[i-p]+fg[i]);
    fg[i-p+1] = (fg[i-p+1]+fg[i]);
  }

  for(i=0;i<p;i++) fg[i] = montproduct( fg[i] , 2721 );
  crypto_encode_pxint16(outbytes,fg);

  return 0;
}

static Fq Fq_bigfreeze(int32_t x) {
    x -= q * ((q14 * x) >> 14);
    x -= q * ((q18 * x) >> 18);
    x -= q * ((q27 * x + 67108864) >> 27);
    x -= q * ((q27 * x + 67108864) >> 27);
    return (Fq) x;
}

static int crypto_core_mult3(uint8_t *outbytes, const uint8_t *inbytes, const uint8_t *kbytes) {
    int8_t *h = (void *) outbytes;
    int8_t f[p];
    int8_t g[p];
    int8_t fg[p + p - 1];
    int16_t result;
    int i, j;

    for (i = 0; i < p; ++i) {
        int8_t fi = (int8_t) inbytes[i];
        int8_t fi0 = fi & 1;
        f[i] = (int8_t) (fi0 - (fi & (fi0 << 1)));
    }
    for (i = 0; i < p; ++i) {
        int8_t gi = (int8_t) kbytes[i];
        int8_t gi0 = gi & 1;
        g[i] = (int8_t) (gi0 - (gi & (gi0 << 1)));
    }

    for (i = 0; i < p; ++i) {
        result = 0;
        for (j = 0; j <= i; ++j) {
            result += (int8_t) (f[j] * g[i - j]);
        }
        fg[i] = F3_freeze(result);
    }
    for (i = p; i < p + p - 1; ++i) {
        result = 0;
        for (j = i - p + 1; j < p; ++j) {
            result += (int8_t) (f[j] * g[i - j]);
        }
        fg[i] = F3_freeze(result);
    }

    for (i = p + p - 2; i >= p; --i) {
        fg[i - p] = F3_freeze(fg[i - p] + fg[i]);
        fg[i - p + 1] = F3_freeze(fg[i - p + 1] + fg[i]);
    }

    for (i = 0; i < p; ++i) {
        h[i] = fg[i];
    }
    return 0;
}


/* out = 1/(3*in) in Rq */
/* outbytes[2*p] is 0 if recip succeeded; else -1 */
static int crypto_core_inv(uint8_t *outbytes, const uint8_t *inbytes) {
    int8_t *in = (void *) inbytes;
    Fq out[p], f[p + 1], g[p + 1], v[p + 1], r[p + 1];
    int i, loop, delta;
    int swap, t;
    int32_t f0, g0;
    Fq scale;

    for (i = 0; i < p + 1; ++i) {
        v[i] = 0;
    }
    for (i = 0; i < p + 1; ++i) {
        r[i] = 0;
    }
    r[0] = Fq_recip(3);
    for (i = 0; i < p; ++i) {
        f[i] = 0;
    }
    f[0] = 1;
    f[p - 1] = f[p] = -1;
    for (i = 0; i < p; ++i) {
        g[p - 1 - i] = (Fq) in[i];
    }
    g[p] = 0;

    delta = 1;

    for (loop = 0; loop < 2 * p - 1; ++loop) {
        for (i = p; i > 0; --i) {
            v[i] = v[i - 1];
        }
        v[0] = 0;

        swap = crypto_int16_negative_mask((int16_t) - delta) & crypto_int16_nonzero_mask(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;

        for (i = 0; i < p + 1; ++i) {
            t = swap & (f[i] ^ g[i]);
            f[i] ^= (Fq) t;
            g[i] ^= (Fq) t;
            t = swap & (v[i] ^ r[i]);
            v[i] ^= (Fq) t;
            r[i] ^= (Fq) t;
        }

        f0 = f[0];
        g0 = g[0];
        for (i = 0; i < p + 1; ++i) {
            g[i] = Fq_bigfreeze(f0 * g[i] - g0 * f[i]);
        }
        for (i = 0; i < p + 1; ++i) {
            r[i] = Fq_bigfreeze(f0 * r[i] - g0 * v[i]);
        }

        for (i = 0; i < p; ++i) {
            g[i] = g[i + 1];
        }
        g[p] = 0;
    }

    scale = Fq_recip(f[0]);
    for (i = 0; i < p; ++i) {
        out[i] = Fq_bigfreeze(scale * (int32_t)v[p - 1 - i]);
    }

    crypto_encode_pxint16(outbytes, out);
    outbytes[2 * p] = (uint8_t) crypto_int16_nonzero_mask((int16_t) delta);
    return 0;
}

/* out = 1/(3*in) in Rq */
/* outbytes[2*p] is 0 if recip succeeded; else -1 */
static int crypto_core_invbig(uint8_t *outbytes, const uint8_t *inbytes)
{
  Fq out[p],f[p+1],g[p+1],v[p+1],r[p+1];
  int i,loop,delta;
  int swap,t;
  int32_t f0,g0;
  Fq scale;

  crypto_decode_pxint16(f,inbytes);
  for (i = 0;i < p;++i) g[p-1-i] = f[i];
  g[p] = 0;

  for (i = 0;i < p+1;++i) v[i] = 0;
  for (i = 0;i < p+1;++i) r[i] = 0;
  r[0] = Fq_recip(3);
  for (i = 0;i < p;++i) f[i] = 0;
  f[0] = 1; f[p-1] = f[p] = -1;

  delta = 1;

  for (loop = 0;loop < 2*p-1;++loop) {
    for (i = p;i > 0;--i) v[i] = v[i-1];
    v[0] = 0;

    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap&(delta^-delta);
    delta += 1;

    for (i = 0;i < p+1;++i) {
      t = swap&(f[i]^g[i]); f[i] ^= t; g[i] ^= t;
      t = swap&(v[i]^r[i]); v[i] ^= t; r[i] ^= t;
    }

    f0 = f[0];
    g0 = g[0];
    for (i = 0;i < p+1;++i) g[i] = Fq_bigfreeze(f0*g[i]-g0*f[i]);
    for (i = 0;i < p+1;++i) r[i] = Fq_bigfreeze(f0*r[i]-g0*v[i]);

    for (i = 0;i < p;++i) g[i] = g[i+1];
    g[p] = 0;
  }

  scale = Fq_recip(f[0]);
  for (i = 0;i < p;++i) out[i] = Fq_bigfreeze(scale*(int32_t)v[p-1-i]);

  crypto_encode_pxint16(outbytes,out);
  outbytes[2*p] = crypto_int16_nonzero_mask(delta);
  return 0;
}


/* R3_fromR(R_fromRq(r)) */
static void R3_fromRq(int8_t *out, const Fq *r) {
    int i;
    for (i = 0; i < p; ++i) out[i] = F3_freeze(r[i]);
}

/* h = f*g in the ring R3 */
static void R3_mult(int8_t *h, const int8_t *f, const int8_t *g) {
	crypto_core_mult3((uint8_t *) h, (const uint8_t *) f, (const uint8_t *) g);
}

/* ----- polynomials mod q */

/* h = f*g in the ring Rq */
static void Rq_mult_small(Fq *h, const Fq *f, const int8_t *g) {
    crypto_encode_pxint16((uint8_t *) h, f);
    crypto_core_mult((uint8_t *) h, (const uint8_t *) h, (const uint8_t *) g);
    crypto_decode_pxint16(h, (const uint8_t *) h);
}

/* h = 3f in Rq */
static void Rq_mult3(Fq *h, const Fq *f) {
	crypto_encode_pxint16((uint8_t *) h, f);
	crypto_core_scale3((uint8_t *) h, (const uint8_t *) h);
	crypto_decode_pxint16(h, (const uint8_t *) h);
}

/* out = 1/(3*in) in Rq */
/* returns 0 if recip succeeded; else -1 */
static void Rq_recip3(Fq *out, const int8_t *in) {
    crypto_core_inv((uint8_t *) out, (const uint8_t *) in);
    /* could check byte 2*p for failure; but, in context, inv always works */
    crypto_decode_pxint16(out, (uint8_t *) out);
}

/* ----- rounded polynomials mod q */

static void Round(Fq *out, const Fq *a) {
    int i;
    for (i = 0; i < p; ++i) out[i] = a[i] - F3_freeze(a[i]);
}

/* ----- sorting to generate short polynomial */

static void Short_fromlist(int8_t *out, const uint32_t *in) {
    uint32_t L[p];
    int i;

    for (i = 0; i < w; ++i) L[i] = in[i] & (uint32_t) -2;
    for (i = w; i < p; ++i) L[i] = (in[i] & (uint32_t) -3) | 1;
    crypto_sort_uint32(L, p);
    for (i = 0; i < p; ++i) out[i] = (L[i] & 3) - 1;
}

/* ----- underlying hash function */

#define Hash_bytes 32

/* e.g., b = 0 means out = Hash0(in) */
static void Hash_prefix(uint8_t *out, int b, const uint8_t *in,
                        int inlen) {
    uint8_t x[inlen + 1];
    uint8_t h[64];
    int i;

    x[0] = b;
    for (i = 0; i < inlen; ++i) x[i + 1] = in[i];
    crypto_hash_sha512(h, x, inlen + 1);
    for (i = 0; i < 32; ++i) out[i] = h[i];
}

/* ----- higher-level randomness */

static uint32_t urandom32(void) {
    uint8_t c[4];
    uint32_t out[4];

    randombytes(c, 4);
    out[0] = (uint32_t) c[0];
    out[1] = ((uint32_t) c[1]) << 8;
    out[2] = ((uint32_t) c[2]) << 16;
    out[3] = ((uint32_t) c[3]) << 24;
    return out[0] + out[1] + out[2] + out[3];
}

static void Short_random(int8_t *out) {
    uint32_t L[p];
    int i;

    for (i = 0; i < p; ++i) L[i] = urandom32();
    Short_fromlist(out, L);
}

static void Small_random(int8_t *out) {
#if 1
	uint32_t L[p];
    int i;

	randombytes((uint8_t *) L, sizeof L);
	crypto_decode_pxint32(L, (uint8_t *) L);
    for (i = 0; i < p; ++i)
        out[i] = (int8_t)((((L[i] & 0x3fffffff) * 3) >> 30) - 1);
#else
    int i;

    for (i = 0; i < p; ++i)
        out[i] = (((urandom32() & 0x3fffffff) * 3) >> 30) - 1;
#endif
}

/* ----- Streamlined NTRU Prime Core */

/* c = Encrypt(r,h) */
static void Encrypt(Fq *c, const int8_t *r, const Fq *h) {
    Fq hr[p];

    Rq_mult_small(hr, h, r);
    Round(c, hr);
}

/* ----- encoding int8_t polynomials (including short polynomials) */

#define Small_bytes ((p + 3) / 4)

/* these are the only functions that rely on p mod 4 = 1 */

static void Small_encode(uint8_t *s, const int8_t *f) {
    int8_t x;
    int i;

    for (i = 0; i < p / 4; ++i) {
        x = *f++ + 1;
        x += (*f++ + 1) << 2;
        x += (*f++ + 1) << 4;
        x += (*f++ + 1) << 6;
        *s++ = x;
    }
    x = *f++ + 1;
    *s++ = x;
}

static void Small_decode(int8_t *f, const uint8_t *s) {
    uint8_t x;
    int i;

    for (i = 0; i < p / 4; ++i) {
        x = *s++;
        *f++ = ((int8_t) (x & 3)) - 1;
        x >>= 2;
        *f++ = ((int8_t) (x & 3)) - 1;
        x >>= 2;
        *f++ = ((int8_t) (x & 3)) - 1;
        x >>= 2;
        *f++ = ((int8_t) (x & 3)) - 1;
    }
    x = *s++;
    *f++ = ((int8_t) (x & 3)) - 1;
}

/* ----- encoding general polynomials */

static void Rq_encode(uint8_t *s, const Fq *r) {
    uint16_t R[p], M[p];
    int i;

    for (i = 0; i < p; ++i) R[i] = r[i] + q12;
    for (i = 0; i < p; ++i) M[i] = q;
    Encode(s, R, M, p);
}

static void Rq_decode(Fq *r, const uint8_t *s) {
    uint16_t R[p], M[p];
    int i;

    for (i = 0; i < p; ++i) M[i] = q;
    Decode(R, s, M, p);
    for (i = 0; i < p; ++i) r[i] = ((Fq) R[i]) - q12;
}

/* ----- encoding rounded polynomials */

static void Rounded_encode(uint8_t *out, const Fq *r) {
    int16_t R0[p];
    /* XXX: caller could overlap R with input */
    uint16_t R[381];
    long i;
    uint16_t r0, r1;
    uint32_t r2;

    for (i = 0; i < p; ++i) R0[i] = (3 * ((10923 * r[i] + 16384) >> 15));
    for (i = 0; i < 380; ++i) {
        r0 = (uint16_t) ((((R0[2 * i] + 2295) & 16383) * 10923) >> 15);
        r1 = (uint16_t) ((((R0[2 * i + 1] + 2295) & 16383) * 10923) >> 15);
        r2 = r0 + r1 * (uint32_t)1531;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }
    R[380] = (uint16_t) ((((R0[760] + 2295) & 16383) * 10923) >> 15);

    for (i = 0; i < 190; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)9157;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }
    R[190] = R[380];

    for (i = 0; i < 95; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)1280;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }
    R[95] = R[190];

    for (i = 0; i < 48; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)6400;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }

    for (i = 0; i < 24; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)625;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }

    for (i = 0; i < 12; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)1526;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }

    for (i = 0; i < 6; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)9097;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }

    for (i = 0; i < 3; ++i) {
        r0 = R[2 * i];
        r1 = R[2 * i + 1];
        r2 = r0 + r1 * (uint32_t)1263;
        *out++ = (uint8_t) r2;
        r2 >>= 8;
        R[i] = (uint16_t) r2;
    }

    r0 = R[0];
    r1 = R[1];
    r2 = r0 + r1 * (uint32_t)6232;
    *out++ = (uint8_t) r2;
    r2 >>= 8;
    *out++ = (uint8_t) r2;
    r2 >>= 8;
    R[0] = (uint16_t) r2;
    R[1] = R[2];

    r0 = R[0];
    r1 = R[1];
    r2 = r0 + r1 * (uint32_t)593;
    *out++ = (uint8_t) r2;
    r2 >>= 8;
    R[0] = (uint16_t) r2;

    r0 = R[0];
    *out++ = (uint8_t) r0;
    r0 >>= 8;
    *out++ = (uint8_t) r0;
}

static void Rounded_decode(void *v, const uint8_t *s)
{
    int16_t *R0 = v;
    uint16_t R1[381], R2[191], R3[96], R4[48], R5[24], R6[12], R7[6], R8[3], R9[2], R10[1];
    long long i;
    uint16_t r0;
    uint32_t r1, r2;

    s += Rounded_bytes;
    r1 = 0;
    r1 = (r1 << 8) | *--s;
    r1 = (r1 << 8) | *--s;
    r1 = uint32_mod_uint14(r1, 3475); /* needed only for invalid inputs */
    R10[0] = (uint16_t) r1;

    r2 = R10[0];
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 593);
    R9[0] = r0;
    r1 = uint32_mod_uint14(r1, 1500); /* needed only for invalid inputs */
    R9[1] = (uint16_t) r1;

    R8[2] = R9[1];
    r2 = R9[0];
    r2 = (r2 << 8) | *--s;
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 6232);
    R8[0] = r0;
    r1 = uint32_mod_uint14(r1, 6232); /* needed only for invalid inputs */
    R8[1] = (uint16_t) r1;

    r2 = R8[2];
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 1263);
    R7[4] = r0;
    r1 = uint32_mod_uint14(r1, 304); /* needed only for invalid inputs */
    R7[5] = (uint16_t) r1;
    for (i = 1; i >= 0; --i) {
        r2 = R8[i];
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 1263);
        R7[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 1263); /* needed only for invalid inputs */
        R7[2 * i + 1] = (uint16_t) r1;
    }

    r2 = R7[5];
    r2 = (r2 << 8) | *--s;
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 9097);
    R6[10] = r0;
    r1 = uint32_mod_uint14(r1, 2188); /* needed only for invalid inputs */
    R6[11] = (uint16_t) r1;
    for (i = 4; i >= 0; --i) {
        r2 = R7[i];
        r2 = (r2 << 8) | *--s;
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 9097);
        R6[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 9097); /* needed only for invalid inputs */
        R6[2 * i + 1] = (uint16_t) r1;
    }

    r2 = R6[11];
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 1526);
    R5[22] = r0;
    r1 = uint32_mod_uint14(r1, 367); /* needed only for invalid inputs */
    R5[23] = (uint16_t) r1;
    for (i = 10; i >= 0; --i) {
        r2 = R6[i];
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 1526);
        R5[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 1526); /* needed only for invalid inputs */
        R5[2 * i + 1] = (uint16_t) r1;
    }

    r2 = R5[23];
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 625);
    R4[46] = r0;
    r1 = uint32_mod_uint14(r1, 150); /* needed only for invalid inputs */
    R4[47] = (uint16_t) r1;
    for (i = 22; i >= 0; --i) {
        r2 = R5[i];
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 625);
        R4[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 625); /* needed only for invalid inputs */
        R4[2 * i + 1] = (uint16_t) r1;
    }

    r2 = R4[47];
    r2 = (r2 << 8) | *--s;
    r2 = (r2 << 8) | *--s;
    uint32_divmod_uint14(&r1, &r0, r2, 6400);
    R3[94] = r0;
    r1 = uint32_mod_uint14(r1, 1531); /* needed only for invalid inputs */
    R3[95] = (uint16_t) r1;
    for (i = 46; i >= 0; --i) {
        r2 = R4[i];
        r2 = (r2 << 8) | *--s;
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 6400);
        R3[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 6400); /* needed only for invalid inputs */
        R3[2 * i + 1] = (uint16_t) r1;
    }

    R2[190] = R3[95];
    for (i = 94; i >= 0; --i) {
        r2 = R3[i];
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 1280);
        R2[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 1280); /* needed only for invalid inputs */
        R2[2 * i + 1] = (uint16_t) r1;
    }

    R1[380] = R2[190];
    for (i = 189; i >= 0; --i) {
        r2 = R2[i];
        r2 = (r2 << 8) | *--s;
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 9157);
        R1[2 * i] = r0;
        r1 = uint32_mod_uint14(r1, 9157); /* needed only for invalid inputs */
        R1[2 * i + 1] = (uint16_t) r1;
    }

    R0[760] = (int16_t) (3 * R1[380] - 2295);
    for (i = 379; i >= 0; --i) {
        r2 = R1[i];
        r2 = (r2 << 8) | *--s;
        uint32_divmod_uint14(&r1, &r0, r2, 1531);
        R0[2 * i] = (int16_t) (3 * r0 - 2295);
        r1 = uint32_mod_uint14(r1, 1531); /* needed only for invalid inputs */
        R0[2 * i + 1] = (int16_t) (3 * r1 - 2295);
    }
}


/* ----- Streamlined NTRU Prime Core plus encoding */

typedef int8_t Inputs[p]; /* passed by reference */
#define Inputs_random Short_random
#define Inputs_encode Small_encode
#define Inputs_bytes Small_bytes

#define Ciphertexts_bytes Rounded_bytes
#define SecretKeys_bytes (2 * Small_bytes)
#define PublicKeys_bytes Rq_bytes

/* pk,sk = ZKeyGen() */
static void ZKeyGen(uint8_t *pk, uint8_t *sk) {
    int8_t f[p], g[p];
    Fq h[p + 1];

    for (;;) {
		int8_t v[p + 1];
		int8_t vp;

		Small_random(g);
		crypto_core_inv3((uint8_t *) v, (const uint8_t *) g);
		vp = v[p];
		if (vp == 0) {
			Small_encode(sk + Small_bytes, v);
			break;
		}
	}

	Short_random(f);
	Small_encode(sk, f);
	Rq_recip3(h, f); /* always works */
	Rq_mult_small(h, h, g);
	Rq_encode(pk, h);
}

/* C = ZEncrypt(r,pk) */
static void ZEncrypt(uint8_t *C, const Inputs r,
                     const uint8_t *pk) {
    Fq h[p];
    Fq c[p];
    Rq_decode(h, pk);
    Encrypt(c, r, h);
    Rounded_encode(C, c);
}

/* r = ZDecrypt(C,sk) */
static void ZDecrypt(Inputs r, const uint8_t *C, const uint8_t *sk) {
	int8_t f[p], e[p], v[p];
	Fq d[p];

	Rounded_decode(d, C);
	Small_decode(f, sk);
	Rq_mult_small(d, d, f);
	Rq_mult3(d, d);
	R3_fromRq(e, d);
	Small_decode(v, sk + Small_bytes);
	R3_mult(r, e, v);
	crypto_core_wforce((uint8_t *)r, (const uint8_t *)r);
}

/* ----- confirmation hash */

#define Confirm_bytes 32

/* h = HashConfirm(r,pk,cache); cache is Hash4(pk) */
static void HashConfirm(uint8_t *h, const uint8_t *r,
                        const uint8_t *pk, const uint8_t *cache) {
    (void) pk;
    uint8_t x[Hash_bytes * 2];
    int i;

    Hash_prefix(x, 3, r, Inputs_bytes);
    for (i = 0; i < Hash_bytes; ++i) x[Hash_bytes + i] = cache[i];
    Hash_prefix(h, 2, x, sizeof x);
}

/* ----- session-key hash */

/* k = HashSession(b,y,z) */
static void HashSession(uint8_t *k, int b, const uint8_t *y,
                        const uint8_t *z) {
    uint8_t x[Hash_bytes + Ciphertexts_bytes + Confirm_bytes];
    int i;

    Hash_prefix(x, 3, y, Inputs_bytes);
    for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; ++i)
        x[Hash_bytes + i] = z[i];
    Hash_prefix(k, b, x, sizeof x);
}

/* ----- Streamlined NTRU Prime and NTRU LPRime */

/* pk,sk = KEM_KeyGen() */
static void KEM_KeyGen(uint8_t *pk, uint8_t *sk) {
    int i;

    ZKeyGen(pk, sk);
    sk += SecretKeys_bytes;
    for (i = 0; i < PublicKeys_bytes; ++i) *sk++ = pk[i];
    randombytes(sk, Inputs_bytes);
    sk += Inputs_bytes;
    Hash_prefix(sk, 4, pk, PublicKeys_bytes);
}

/* c,r_enc = Hide(r,pk,cache); cache is Hash4(pk) */
static void Hide(uint8_t *c, uint8_t *r_enc, const Inputs r,
                 const uint8_t *pk, const uint8_t *cache) {
    Inputs_encode(r_enc, r);
    ZEncrypt(c, r, pk);
    c += Ciphertexts_bytes;
    HashConfirm(c, r_enc, pk, cache);
}

/* c,k = Encap(pk) */
static void Encap(uint8_t *c, uint8_t *k, const uint8_t *pk) {
    Inputs r;
    uint8_t r_enc[Inputs_bytes];
    uint8_t cache[Hash_bytes];

    Hash_prefix(cache, 4, pk, PublicKeys_bytes);
    Inputs_random(r);
    Hide(c, r_enc, r, pk, cache);
    HashSession(k, 1, r_enc, c);
}

/* 0 if matching ciphertext+confirm, else -1 */
static int Ciphertexts_diff_mask(const uint8_t *c,
                                 const uint8_t *c2) {
    uint16_t differentbits = 0;
    int len = Ciphertexts_bytes + Confirm_bytes;

    while (len-- > 0) differentbits |= (*c++) ^ (*c2++);
    return crypto_int16_nonzero_mask(differentbits);
}

/* k = Decap(c,sk) */
static void Decap(uint8_t *k, const uint8_t *c,
                  const uint8_t *sk) {
    const uint8_t *pk = sk + SecretKeys_bytes;
    const uint8_t *rho = pk + PublicKeys_bytes;
    const uint8_t *cache = rho + Inputs_bytes;
    Inputs r;
    uint8_t r_enc[Inputs_bytes];
    uint8_t cnew[Ciphertexts_bytes + Confirm_bytes];
    int mask;
    int i;

    ZDecrypt(r, c, sk);
    Hide(cnew, r_enc, r, pk, cache);
    mask = Ciphertexts_diff_mask(c, cnew);
    for (i = 0; i < Inputs_bytes; ++i) r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
    HashSession(k, 1 + mask, r_enc, c);
}

static int sntrup761_batch_keypair(uint8_t *pk, uint8_t *sk, size_t n)
{
	int8_t *buf, *_f, *f, *_g, *g, *ginv, *gs, *v;
	Fq temp[p + 1], *_finv, *finv, *fs;
	uint8_t *sk_cur, *pk_cur;

	if (n == 1) {
		KEM_KeyGen(pk, sk);
		return 0;
	}

	buf = calloc(n, 4 * p);
	f = _f = buf;
	g = _g = _f + p * n;
	finv = _finv = (Fq *)(_g + p * n);

	/* generate secret keys */
	sk_cur = sk;
	for (size_t i = 0; i < n; i++, f += p, g += p, sk_cur += SNTRUP761_SEC_SIZE) {
		for (;;) {
			int8_t *v = (int8_t *)temp;
			Small_random(g);
			crypto_core_iszeromod3((uint8_t *)v, (const uint8_t *)g);
			if (!v[0])
				break;
		}

		Short_random(f);
		randombytes(sk_cur + SecretKeys_bytes + PublicKeys_bytes, Small_bytes);
	}

	/* calculate secret keys */
	v = (int8_t *)temp;
	gs = (int8_t *)_finv;
	g = _g;
	memcpy(gs, g, p);
	g += p;

	for (size_t i = 1; i < n; i++, gs += p, g += p)
		crypto_core_mult3((uint8_t *)&gs[p], (const uint8_t *)gs, (const uint8_t *)g);

	crypto_core_inv3((uint8_t *)v, (const uint8_t *)gs);

	ginv = gs;
	gs -= p;
	g -= p;
	for (size_t i = n - 1; i >= 2; i--, ginv -= p, gs -= p, g -= p) {
		crypto_core_mult3((uint8_t *)ginv, (const uint8_t *)v, (const uint8_t *)gs);
		crypto_core_mult3((uint8_t *)v, (const uint8_t *)v, (const uint8_t *)g);
	}

	ginv = (int8_t *)_finv;
	g = _g;
	sk_cur = sk;
	crypto_core_mult3((uint8_t *)&ginv[p], (const uint8_t *)v, (const uint8_t *)g);
	crypto_core_mult3((uint8_t *)ginv, (const uint8_t *)v, (const uint8_t *)&g[p]);
	for (size_t i = 0; i < n; i++, sk_cur += SNTRUP761_SEC_SIZE, ginv += p)
		Small_encode(sk_cur + Small_bytes, ginv);

	/* calculate public keys */
	fs = _finv;
	f = _f;
	for (size_t i = 0; i < p; i++)
		fs[i] = f[i];

	crypto_encode_pxint16((uint8_t *) fs, fs);
	for (size_t i = 1; i < n; i++, fs += p, f += p)
		crypto_core_mult((uint8_t *)&fs[p], (const uint8_t *)fs, (const uint8_t *)&f[p]);

	crypto_core_invbig((uint8_t *)temp, (const uint8_t *)fs);

	finv = fs;
	fs -= p;
	for (size_t i = n - 1; i >= 2; i--, finv -= p, fs -= p, f -= p) {
		crypto_core_multbig((uint8_t *)finv, (const uint8_t *)temp, (const uint8_t *)fs);
		crypto_core_mult((uint8_t *)temp, (const uint8_t *)temp, (const uint8_t *)f);
	}

	finv = _finv;
	f = _f;
	crypto_core_mult((uint8_t *)&finv[p], (const uint8_t *)temp, (const uint8_t *)f);
	crypto_core_mult((uint8_t *)finv, (const uint8_t *)temp, (const uint8_t *)&f[p]);

	g = _g;
	pk_cur = pk;
	for (size_t i = 0; i < n; i++, finv += p, g += p, pk_cur += PublicKeys_bytes) {
		crypto_core_mult((uint8_t *)temp, (const uint8_t *)finv, (const uint8_t *)g);
		Rq_encode(pk_cur, temp);
	}

	/* encode secret keys */
	sk_cur = sk;
	pk_cur = pk;
	f = _f;
	for (size_t i = 0; i < n; i++, sk_cur += SNTRUP761_SEC_SIZE, pk_cur += PublicKeys_bytes, f += p) {
		uint8_t *skp = sk_cur;

		Small_encode(skp, f);
		skp += SecretKeys_bytes;

		memcpy(skp, pk_cur, PublicKeys_bytes);
		skp += PublicKeys_bytes + Inputs_bytes;
		Hash_prefix(skp, 4, pk_cur, PublicKeys_bytes);
	}
	free(buf);

	return 0;
}

static int batch_user_max = 2;
static int batch_cur = 0, batch_max = 0;
static uint8_t *batch_pk, *batch_sk;

static void
sntrup761_batch_alloc(void)
{
	batch_max = batch_user_max;
	batch_pk = calloc(batch_max, SNTRUP761_PUB_SIZE + SNTRUP761_SEC_SIZE);
	batch_sk = batch_pk + batch_max * SNTRUP761_PUB_SIZE;
}

static void move_key(uint8_t *dest, uint8_t *src, size_t len)
{
	memcpy(dest, src, len);
	memset(src, 0, len);
}

void sntrup761_set_batch(int val)
{
#ifndef SNTRUP761_KEYGEN_BATCH
	return;
#endif
	free(batch_pk);
	batch_pk = NULL;
	batch_sk = NULL;
	batch_user_max = val;
	batch_max = 0;
}

int sntrup761_keypair(uint8_t *pk, uint8_t *sk)
{
	uint8_t *cur_pk, *cur_sk;

#ifndef SNTRUP761_KEYGEN_BATCH
	KEM_KeyGen(pk, sk);
	return 0;
#endif

	if (batch_user_max < 2) {
	    KEM_KeyGen(pk, sk);
		return 0;
	}

	if (batch_cur < batch_max)
		goto next;

	if (!batch_max)
		sntrup761_batch_alloc();

	batch_cur = 0;
	sntrup761_batch_keypair(batch_pk, batch_sk, batch_max);

next:
	cur_pk = batch_pk + batch_cur * SNTRUP761_PUB_SIZE;
	cur_sk = batch_sk + batch_cur * SNTRUP761_SEC_SIZE;
	move_key(pk, cur_pk, SNTRUP761_PUB_SIZE);
	move_key(sk, cur_sk, SNTRUP761_SEC_SIZE);
	batch_cur++;

    return 0;
}

int sntrup761_enc(uint8_t *c, uint8_t *k, const uint8_t *pk)
{
    Encap(c, k, pk);
    return 0;
}

int sntrup761_dec(uint8_t *k, const uint8_t *c, const uint8_t *sk)
{
    Decap(k, c, sk);
    return 0;
}
