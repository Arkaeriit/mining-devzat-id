// Monocypher version 2.0.6

#include "monocypher.h"
#include "zero.h"

/////////////////
/// Utilities ///
/////////////////

#define HASH_NAME cf_sha512
#define COMBINE1(x, y) x ## y
#define COMBINE2(x, y) COMBINE1(x, y)
#define HASH_CTX    COMBINE2(HASH_NAME, _context)
#define HASH_INIT   COMBINE2(HASH_NAME, _init)
#define HASH_UPDATE COMBINE2(HASH_NAME, _update)
#define HASH_FINAL  COMBINE2(HASH_NAME, _digest_final)
#define HASH(a, data, size) { \
	HASH_CTX hash_ctx; \
	HASH_INIT(&hash_ctx); \
	HASH_UPDATE(&hash_ctx, data, size); \
	HASH_FINAL(&hash_ctx, a); \
}

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))
#define ALIGN(x, block_size)       ((~(x) + 1) & ((block_size) - 1))
typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

static u32 load24_le(const u8 s[3])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16);
}

static u32 load32_le(const u8 s[4])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16)
        | ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
    return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store32_le(u8 out[4], u32 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

static int neq0(u64 diff)
{   // constant time comparison to zero
    // return diff != 0 ? -1 : 0
    u64 half = (diff >> 32) | ((u32)diff);
    return (1 & ((half - 1) >> 32)) - 1;
}

static u64 x16(const u8 a[16], const u8 b[16])
{
    return (load64_le(a + 0) ^ load64_le(b + 0))
        |  (load64_le(a + 8) ^ load64_le(b + 8));
}
static u64 x32(const u8 a[32],const u8 b[32]){return x16(a,b)| x16(a+16, b+16);}
static int crypto_verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }

static int zerocmp32(const u8 p[32])
{
    return crypto_verify32(p, zero);
}

static void crypto_wipe(void *secret, size_t size)
{
    volatile u8 *v_secret = (u8*)secret;
    FOR (i, 0, size) {
        v_secret[i] = 0;
    }
}

////////////////////////////////////
/// Arithmetic modulo 2^255 - 19 ///
////////////////////////////////////
//  Taken from SUPERCOP's ref10 implementation.
//  A bit bigger than TweetNaCl, over 4 times faster.

// field element
typedef i32 fe[10];

static void fe_0(fe h) {            FOR(i, 0, 10) h[i] = 0; }
static void fe_1(fe h) { h[0] = 1;  FOR(i, 1, 10) h[i] = 0; }

static void fe_copy(fe h,const fe f           ){FOR(i,0,10) h[i] =  f[i];      }
static void fe_neg (fe h,const fe f           ){FOR(i,0,10) h[i] = -f[i];      }
static void fe_add (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] + g[i];}
static void fe_sub (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] - g[i];}

static void fe_cswap(fe f, fe g, int b)
{
    i32 mask = -b; // rely on 2's complement: -1 = 0xffffffff
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & mask;
        f[i] = f[i] ^ x;
        g[i] = g[i] ^ x;
    }
}

static void fe_ccopy(fe f, const fe g, int b)
{
    i32 mask = -b; // rely on 2's complement: -1 = 0xffffffff
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & mask;
        f[i] = f[i] ^ x;
    }
}

#define FE_CARRY                                                        \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                         \
    c9 = (t9 + (i64)(1<<24)) >> 25; t0 += c9 * 19; t9 -= c9 * (1 << 25); \
    c1 = (t1 + (i64)(1<<24)) >> 25; t2 += c1;      t1 -= c1 * (1 << 25); \
    c3 = (t3 + (i64)(1<<24)) >> 25; t4 += c3;      t3 -= c3 * (1 << 25); \
    c5 = (t5 + (i64)(1<<24)) >> 25; t6 += c5;      t5 -= c5 * (1 << 25); \
    c7 = (t7 + (i64)(1<<24)) >> 25; t8 += c7;      t7 -= c7 * (1 << 25); \
    c0 = (t0 + (i64)(1<<25)) >> 26; t1 += c0;      t0 -= c0 * (1 << 26); \
    c2 = (t2 + (i64)(1<<25)) >> 26; t3 += c2;      t2 -= c2 * (1 << 26); \
    c4 = (t4 + (i64)(1<<25)) >> 26; t5 += c4;      t4 -= c4 * (1 << 26); \
    c6 = (t6 + (i64)(1<<25)) >> 26; t7 += c6;      t6 -= c6 * (1 << 26); \
    c8 = (t8 + (i64)(1<<25)) >> 26; t9 += c8;      t8 -= c8 * (1 << 26); \
    h[0]=(i32)t0;  h[1]=(i32)t1;  h[2]=(i32)t2;  h[3]=(i32)t3;  h[4]=(i32)t4; \
    h[5]=(i32)t5;  h[6]=(i32)t6;  h[7]=(i32)t7;  h[8]=(i32)t8;  h[9]=(i32)t9

static void fe_frombytes(fe h, const u8 s[32])
{
    i64 t0 =  load32_le(s);
    i64 t1 =  load24_le(s +  4) << 6;
    i64 t2 =  load24_le(s +  7) << 5;
    i64 t3 =  load24_le(s + 10) << 3;
    i64 t4 =  load24_le(s + 13) << 2;
    i64 t5 =  load32_le(s + 16);
    i64 t6 =  load24_le(s + 20) << 7;
    i64 t7 =  load24_le(s + 23) << 5;
    i64 t8 =  load24_le(s + 26) << 4;
    i64 t9 = (load24_le(s + 29) & 0x7fffff) << 2;
    FE_CARRY;
}

static void fe_mul_small(fe h, const fe f, i32 g)
{
    i64 t0 = f[0] * (i64) g;  i64 t1 = f[1] * (i64) g;
    i64 t2 = f[2] * (i64) g;  i64 t3 = f[3] * (i64) g;
    i64 t4 = f[4] * (i64) g;  i64 t5 = f[5] * (i64) g;
    i64 t6 = f[6] * (i64) g;  i64 t7 = f[7] * (i64) g;
    i64 t8 = f[8] * (i64) g;  i64 t9 = f[9] * (i64) g;
    FE_CARRY;
}
static void fe_mul121666(fe h, const fe f) { fe_mul_small(h, f, 121666); }

static void fe_mul(fe h, const fe f, const fe g)
{
    // Everything is unrolled and put in temporary variables.
    // We could roll the loop, but that would make curve25519 twice as slow.
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 = g[3]; i32 g4 = g[4];
    i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 = g[8]; i32 g9 = g[9];
    i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 = f7*2; i32 F9 = f9*2;
    i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
    i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
    i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;

    i64 h0 = f0*(i64)g0 + F1*(i64)G9 + f2*(i64)G8 + F3*(i64)G7 + f4*(i64)G6
        +    F5*(i64)G5 + f6*(i64)G4 + F7*(i64)G3 + f8*(i64)G2 + F9*(i64)G1;
    i64 h1 = f0*(i64)g1 + f1*(i64)g0 + f2*(i64)G9 + f3*(i64)G8 + f4*(i64)G7
        +    f5*(i64)G6 + f6*(i64)G5 + f7*(i64)G4 + f8*(i64)G3 + f9*(i64)G2;
    i64 h2 = f0*(i64)g2 + F1*(i64)g1 + f2*(i64)g0 + F3*(i64)G9 + f4*(i64)G8
        +    F5*(i64)G7 + f6*(i64)G6 + F7*(i64)G5 + f8*(i64)G4 + F9*(i64)G3;
    i64 h3 = f0*(i64)g3 + f1*(i64)g2 + f2*(i64)g1 + f3*(i64)g0 + f4*(i64)G9
        +    f5*(i64)G8 + f6*(i64)G7 + f7*(i64)G6 + f8*(i64)G5 + f9*(i64)G4;
    i64 h4 = f0*(i64)g4 + F1*(i64)g3 + f2*(i64)g2 + F3*(i64)g1 + f4*(i64)g0
        +    F5*(i64)G9 + f6*(i64)G8 + F7*(i64)G7 + f8*(i64)G6 + F9*(i64)G5;
    i64 h5 = f0*(i64)g5 + f1*(i64)g4 + f2*(i64)g3 + f3*(i64)g2 + f4*(i64)g1
        +    f5*(i64)g0 + f6*(i64)G9 + f7*(i64)G8 + f8*(i64)G7 + f9*(i64)G6;
    i64 h6 = f0*(i64)g6 + F1*(i64)g5 + f2*(i64)g4 + F3*(i64)g3 + f4*(i64)g2
        +    F5*(i64)g1 + f6*(i64)g0 + F7*(i64)G9 + f8*(i64)G8 + F9*(i64)G7;
    i64 h7 = f0*(i64)g7 + f1*(i64)g6 + f2*(i64)g5 + f3*(i64)g4 + f4*(i64)g3
        +    f5*(i64)g2 + f6*(i64)g1 + f7*(i64)g0 + f8*(i64)G9 + f9*(i64)G8;
    i64 h8 = f0*(i64)g8 + F1*(i64)g7 + f2*(i64)g6 + F3*(i64)g5 + f4*(i64)g4
        +    F5*(i64)g3 + f6*(i64)g2 + F7*(i64)g1 + f8*(i64)g0 + F9*(i64)G9;
    i64 h9 = f0*(i64)g9 + f1*(i64)g8 + f2*(i64)g7 + f3*(i64)g6 + f4*(i64)g5
        +    f5*(i64)g4 + f6*(i64)g3 + f7*(i64)g2 + f8*(i64)g1 + f9*(i64)g0;

#define CARRY                                                             \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                           \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 * (1 << 26); \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 * (1 << 26); \
    c1 = (h1 + (i64) (1<<24)) >> 25; h2 += c1;      h1 -= c1 * (1 << 25); \
    c5 = (h5 + (i64) (1<<24)) >> 25; h6 += c5;      h5 -= c5 * (1 << 25); \
    c2 = (h2 + (i64) (1<<25)) >> 26; h3 += c2;      h2 -= c2 * (1 << 26); \
    c6 = (h6 + (i64) (1<<25)) >> 26; h7 += c6;      h6 -= c6 * (1 << 26); \
    c3 = (h3 + (i64) (1<<24)) >> 25; h4 += c3;      h3 -= c3 * (1 << 25); \
    c7 = (h7 + (i64) (1<<24)) >> 25; h8 += c7;      h7 -= c7 * (1 << 25); \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 * (1 << 26); \
    c8 = (h8 + (i64) (1<<25)) >> 26; h9 += c8;      h8 -= c8 * (1 << 26); \
    c9 = (h9 + (i64) (1<<24)) >> 25; h0 += c9 * 19; h9 -= c9 * (1 << 25); \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 * (1 << 26); \
    h[0]=(i32)h0;  h[1]=(i32)h1;  h[2]=(i32)h2;  h[3]=(i32)h3;  h[4]=(i32)h4; \
    h[5]=(i32)h5;  h[6]=(i32)h6;  h[7]=(i32)h7;  h[8]=(i32)h8;  h[9]=(i32)h9

    CARRY;
}

// we could use fe_mul() for this, but this is significantly faster
static void fe_sq(fe h, const fe f)
{
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 f0_2  = f0*2;   i32 f1_2  = f1*2;   i32 f2_2  = f2*2;   i32 f3_2 = f3*2;
    i32 f4_2  = f4*2;   i32 f5_2  = f5*2;   i32 f6_2  = f6*2;   i32 f7_2 = f7*2;
    i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
    i32 f8_19 = f8*19;  i32 f9_38 = f9*38;

    i64 h0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
        +    f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
    i64 h1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
        +    f4  *(i64)f7_38 + f5_2*(i64)f6_19;
    i64 h2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
        +    f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
    i64 h3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
        +    f5_2*(i64)f8_19 + f6  *(i64)f7_38;
    i64 h4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
        +    f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
    i64 h5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
        +    f6  *(i64)f9_38 + f7_2*(i64)f8_19;
    i64 h6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
        +    f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
    i64 h7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
        +    f3_2*(i64)f4    + f8  *(i64)f9_38;
    i64 h8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
        +    f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
    i64 h9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
        +    f3_2*(i64)f6    + f4  *(i64)f5_2;

    CARRY;
}

static void fe_sq2(fe h, const fe f)
{
    fe_sq(h, f);
    fe_mul_small(h, h, 2);
}

// This could be simplified, but it would be slower
static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sq(t0, z );
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1,  z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);                                fe_mul(t1 , t1, t2);
    fe_sq(t2, t1); FOR (i, 1,   5) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1,  20) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1, 100) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t1, t1); FOR (i, 1,   5) fe_sq(t1, t1); fe_mul(out, t1, t0);
    WIPE_BUFFER(t0);
    WIPE_BUFFER(t1);
    WIPE_BUFFER(t2);
    WIPE_BUFFER(t3);
}

// This could be simplified, but it would be slower
static void fe_pow22523(fe out, const fe z)
{
    fe t0, t1, t2;
    fe_sq(t0, z);
    fe_sq(t1,t0);                   fe_sq(t1, t1);  fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);                                  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,   5) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1,  20) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1, 100) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t0, t0);  FOR (i, 1,   2) fe_sq(t0, t0);  fe_mul(out, t0, z);
    WIPE_BUFFER(t0);
    WIPE_BUFFER(t1);
    WIPE_BUFFER(t2);
}

static void fe_tobytes(u8 s[32], const fe h)
{
    i32 t[10];
    FOR (i, 0, 10) {
        t[i] = h[i];
    }
    i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
    FOR (i, 0, 5) {
        q += t[2*i  ]; q >>= 26;
        q += t[2*i+1]; q >>= 25;
    }
    t[0] += 19 * q;

    i32 c0 = t[0] >> 26; t[1] += c0; t[0] -= c0 * (1 << 26);
    i32 c1 = t[1] >> 25; t[2] += c1; t[1] -= c1 * (1 << 25);
    i32 c2 = t[2] >> 26; t[3] += c2; t[2] -= c2 * (1 << 26);
    i32 c3 = t[3] >> 25; t[4] += c3; t[3] -= c3 * (1 << 25);
    i32 c4 = t[4] >> 26; t[5] += c4; t[4] -= c4 * (1 << 26);
    i32 c5 = t[5] >> 25; t[6] += c5; t[5] -= c5 * (1 << 25);
    i32 c6 = t[6] >> 26; t[7] += c6; t[6] -= c6 * (1 << 26);
    i32 c7 = t[7] >> 25; t[8] += c7; t[7] -= c7 * (1 << 25);
    i32 c8 = t[8] >> 26; t[9] += c8; t[8] -= c8 * (1 << 26);
    i32 c9 = t[9] >> 25;             t[9] -= c9 * (1 << 25);

    store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
    store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
    store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
    store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
    store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
    store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
    store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
    store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));

    WIPE_BUFFER(t);
}

//  Parity check.  Returns 0 if even, 1 if odd
static int fe_isnegative(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    u8 isneg = s[0] & 1;
    WIPE_BUFFER(s);
    return isneg;
}

static int fe_isnonzero(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    int isnonzero = zerocmp32(s);
    WIPE_BUFFER(s);
    return isnonzero;
}

static void trim_scalar(u8 s[32])
{
    s[ 0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

static int scalar_bit(const u8 s[32], int i) {
    if (i < 0) { return 0; } // handle -1 for sliding windows
    return (s[i>>3] >> (i&7)) & 1;
}

///////////////
/// X-25519 /// Taken from SUPERCOP's ref10 implementation.
///////////////

int crypto_x25519(u8       raw_shared_secret[32],
                  const u8 your_secret_key  [32],
                  const u8 their_public_key [32])
{
    // computes the scalar product
    fe x1;
    fe_frombytes(x1, their_public_key);

    // restrict the possible scalar values
    u8 e[32];
    FOR (i, 0, 32) {
        e[i] = your_secret_key[i];
    }
    trim_scalar(e);

    // computes the actual scalar product (the result is in x2 and z2)
    fe x2, z2, x3, z3, t0, t1;
    // Montgomery ladder
    // In projective coordinates, to avoid divisions: x = X / Z
    // We don't care about the y coordinate, it's only 1 bit of information
    fe_1(x2);        fe_0(z2); // "zero" point
    fe_copy(x3, x1); fe_1(z3); // "one"  point
    int swap = 0;
    for (int pos = 254; pos >= 0; --pos) {
        // constant time conditional swap before ladder step
        int b = scalar_bit(e, pos);
        swap ^= b; // xor trick avoids swapping at the end of the loop
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;  // anticipates one last swap after the loop

        // Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
        // with differential addition
        fe_sub(t0, x3, z3);  fe_sub(t1, x2, z2);    fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);  fe_mul(z3, t0, x2);    fe_mul(z2, z2, t1);
        fe_sq (t0, t1    );  fe_sq (t1, x2    );    fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);  fe_mul(x2, t1, t0);    fe_sub(t1, t1, t0);
        fe_sq (z2, z2    );  fe_mul121666(z3, t1);  fe_sq (x3, x3    );
        fe_add(t0, t0, z3);  fe_mul(z3, x1, z2);    fe_mul(z2, t1, t0);
    }
    // last swap is necessary to compensate for the xor trick
    // Note: after this swap, P3 == P2 + P1.
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    // normalises the coordinates: x == X / Z
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(raw_shared_secret, x2);

    WIPE_BUFFER(x1);  WIPE_BUFFER(e );
    WIPE_BUFFER(x2);  WIPE_BUFFER(z2);
    WIPE_BUFFER(x3);  WIPE_BUFFER(z3);
    WIPE_BUFFER(t0);  WIPE_BUFFER(t1);

    // Returns -1 if the output is all zero
    // (happens with some malicious public keys)
    return -1 - zerocmp32(raw_shared_secret);
}

void crypto_x25519_public_key(u8       public_key[32],
                              const u8 secret_key[32])
{
    static const u8 base_point[32] = {9};
    crypto_x25519(public_key, secret_key, base_point);
}

///////////////
/// Ed25519 ///
///////////////

static const  i64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

static void modL(u8 *r, i64 x[64])
{
    for (unsigned i = 63; i >= 32; i--) {
        i64 carry = 0;
        FOR (j, i-32, i-12) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * (1 << 8);
        }
        x[i-12] += carry;
        x[i] = 0;
    }
    i64 carry = 0;
    FOR (i, 0, 32) {
        x[i] += carry - (x[31] >> 4) * L[i];
        carry = x[i] >> 8;
        x[i] &= 255;
    }
    FOR (i, 0, 32) {
        x[i] -= carry * L[i];
    }
    FOR (i, 0, 32) {
        x[i+1] += x[i] >> 8;
        r[i  ]  = x[i] & 255;
    }
}

// Reduces a hash modulo L (little endian)
static void reduce(u8 r[64])
{
    i64 x[64];
    FOR (i, 0, 64) {
        x[i] = (i64)(u64)r[i]; // preserve unsigned
        r[i] = 0;
    }
    modL(r, x);
    WIPE_BUFFER(x);
}

// r = (a * b) + c
static void mul_add(u8 r[32], const u8 a[32], const u8 b[32], const u8 c[32])
{
    i64 s[64];
    FOR (i,  0, 32) { s[i] = (i64)(u64)c[i]; } // preserve unsigned
    FOR (i, 32, 64) { s[i] = 0;              }
    FOR (i,  0, 32) {
        FOR (j, 0, 32) {
            s[i+j] += a[i] * (u64)b[j];
        }
    }
    modL(r, s);
    WIPE_BUFFER(s);
}

// Variable time! a must not be secret!
static int is_above_L(const u8 a[32])
{
    for (int i = 31; i >= 0; i--) {
        if (a[i] > L[i]) { return 1; }
        if (a[i] < L[i]) { return 0; }
    }
    return 1;
}

// Point in a twisted Edwards curve,
// in extended projective coordinates.
// x = X/Z, y = Y/Z, T = XY/Z
typedef struct { fe X;  fe Y;  fe Z; fe T;  } ge;
typedef struct { fe Yp; fe Ym; fe Z; fe T2; } ge_cached;

static void ge_zero(ge *p)
{
    fe_0(p->X);
    fe_1(p->Y);
    fe_1(p->Z);
    fe_0(p->T);
}

static void ge_tobytes(u8 s[32], const ge *h)
{
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;

    WIPE_BUFFER(recip);
    WIPE_BUFFER(x);
    WIPE_BUFFER(y);
}

// Variable time! s must not be secret!
static int ge_frombytes_neg_vartime(ge *h, const u8 s[32])
{
    static const fe d = {
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    } ;
    static const fe sqrtm1 = {
        -32595792, -7943725, 9377950, 3500415, 12389472,
        -272473, -25146209, -2005654, 326686, 11406482
    } ;
    fe u, v, v3; // no secret, no wipe
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);            // y^2
    fe_mul(v, u, d);
    fe_sub(u, u, h->Z);        // u = y^2-1
    fe_add(v, v, h->Z);        // v = dy^2+1

    fe_sq(v3, v);
    fe_mul(v3, v3, v);         // v3 = v^3
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u);     // x = uv^7

    fe_pow22523(h->X, h->X);   // x = (uv^7)^((q-5)/8)
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);     // x = uv^3(uv^7)^((q-5)/8)

    fe vxx, check; // no secret, no wipe
    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);     // vx^2-u
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u); // vx^2+u
        if (fe_isnonzero(check)) {
            return -1;
        }
        fe_mul(h->X, h->X, sqrtm1);
    }
    if (fe_isnegative(h->X) == (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

static void ge_cache(ge_cached *c, const ge *p)
{
    static const fe D2 = { // - 2 * 121665 / 121666
        -21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199
    };
    fe_add (c->Yp, p->Y, p->X);
    fe_sub (c->Ym, p->Y, p->X);
    fe_copy(c->Z , p->Z      );
    fe_mul (c->T2, p->T, D2  );
}

static void ge_add(ge *s, const ge *p, const ge_cached *q)
{
    fe a, b; // not used to process secrets, no need to wipe
    fe_add(a   , p->Y, p->X );
    fe_sub(b   , p->Y, p->X );
    fe_mul(a   , a   , q->Yp);
    fe_mul(b   , b   , q->Ym);
    fe_add(s->Y, a   , b    );
    fe_sub(s->X, a   , b    );

    fe_add(s->Z, p->Z, p->Z );
    fe_mul(s->Z, s->Z, q->Z );
    fe_mul(s->T, p->T, q->T2);
    fe_add(a   , s->Z, s->T );
    fe_sub(b   , s->Z, s->T );

    fe_mul(s->T, s->X, s->Y);
    fe_mul(s->X, s->X, b   );
    fe_mul(s->Y, s->Y, a   );
    fe_mul(s->Z, a   , b   );
}

static void ge_sub(ge *s, const ge *p, const ge_cached *q)
{
    ge_cached neg;
    fe_copy(neg.Ym, q->Yp);
    fe_copy(neg.Yp, q->Ym);
    fe_copy(neg.Z , q->Z );
    fe_neg (neg.T2, q->T2);
    ge_add(s, p, &neg);
}

static void ge_madd(ge *s, const ge *p, const fe yp, const fe ym, const fe t2,
                    fe a, fe b)
{
    fe_add(a   , p->Y, p->X );
    fe_sub(b   , p->Y, p->X );
    fe_mul(a   , a   , yp   );
    fe_mul(b   , b   , ym   );
    fe_add(s->Y, a   , b    );
    fe_sub(s->X, a   , b    );

    fe_add(s->Z, p->Z, p->Z );
    fe_mul(s->T, p->T, t2   );
    fe_add(a   , s->Z, s->T );
    fe_sub(b   , s->Z, s->T );

    fe_mul(s->T, s->X, s->Y);
    fe_mul(s->X, s->X, b   );
    fe_mul(s->Y, s->Y, a   );
    fe_mul(s->Z, a   , b   );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_msub(ge *s, const ge *p, const fe yp, const fe ym, const fe t2,
                    fe a, fe b)
{
    fe n2;
    fe_neg(n2, t2);
    ge_madd(s, p, ym, yp, n2, a, b);
}

static void ge_double(ge *s, const ge *p, ge *q)
{
    fe_sq (q->X, p->X);
    fe_sq (q->Y, p->Y);
    fe_sq2(q->Z, p->Z);
    fe_add(q->T, p->X, p->Y);
    fe_sq (s->T, q->T);
    fe_add(q->T, q->Y, q->X);
    fe_sub(q->Y, q->Y, q->X);
    fe_sub(q->X, s->T, q->T);
    fe_sub(q->Z, q->Z, q->Y);

    fe_mul(s->X, q->X , q->Z);
    fe_mul(s->Y, q->T , q->Y);
    fe_mul(s->Z, q->Y , q->Z);
    fe_mul(s->T, q->X , q->T);
}

static const fe window_Yp[8] = {
    {25967493, -14356035, 29566456, 3660896, -12694345,
     4014787, 27544626, -11754271, -6079156, 2047605},
    {15636291, -9688557, 24204773, -7912398, 616977,
     -16685262, 27787600, -14772189, 28944400, -1550024},
    {10861363, 11473154, 27284546, 1981175, -30064349,
     12577861, 32867885, 14515107, -15438304, 10819380},
    {5153746, 9909285, 1723747, -2777874, 30523605,
     5516873, 19480852, 5230134, -23952439, -15175766},
    {-22518993, -6692182, 14201702, -8745502, -23510406,
     8844726, 18474211, -1361450, -13062696, 13821877},
    {-25154831, -4185821, 29681144, 7868801, -6854661,
     -9423865, -12437364, -663000, -31111463, -16132436},
    {-33521811, 3180713, -2394130, 14003687, -16903474,
     -16270840, 17238398, 4729455, -18074513, 9256800},
    {-3151181, -5046075, 9282714, 6866145, -31907062,
     -863023, -18940575, 15033784, 25105118, -7894876},
};
static const fe window_Ym[8] = {
    {-12545711, 934262, -2722910, 3049990, -727428,
     9406986, 12720692, 5043384, 19500929, -15469378},
    {16568933, 4717097, -11556148, -1102322, 15682896,
     -11807043, 16354577, -11775962, 7689662, 11199574},
    {4708026, 6336745, 20377586, 9066809, -11272109,
     6594696, -25653668, 12483688, -12668491, 5581306},
    {-30269007, -3463509, 7665486, 10083793, 28475525,
     1649722, 20654025, 16520125, 30598449, 7715701},
    {-6455177, -7839871, 3374702, -4740862, -27098617,
     -10571707, 31655028, -7212327, 18853322, -14220951},
    {25576264, -2703214, 7349804, -11814844, 16472782,
     9300885, 3844789, 15725684, 171356, 6466918},
    {-25182317, -4174131, 32336398, 5036987, -21236817,
     11360617, 22616405, 9761698, -19827198, 630305},
    {-24326370, 15950226, -31801215, -14592823, -11662737,
     -5090925, 1573892, -2625887, 2198790, -15804619},
};
static const fe window_T2[8] = {
    {-8738181, 4489570, 9688441, -14785194, 10184609,
     -12363380, 29287919, 11864899, -24514362, -4438546},
    {30464156, -5976125, -11779434, -15670865, 23220365,
     15915852, 7512774, 10017326, -17749093, -9920357},
    {19563160, 16186464, -29386857, 4097519, 10237984,
     -4348115, 28542350, 13850243, -23678021, -15815942},
    {28881845, 14381568, 9657904, 3680757, -20181635,
     7843316, -31400660, 1370708, 29794553, -1409300},
    {4566830, -12963868, -28974889, -12240689, -7602672,
     -2830569, -8514358, -10431137, 2207753, -3209784},
    {23103977, 13316479, 9739013, -16149481, 817875,
     -15038942, 8965339, -14088058, -30714912, 16193877},
    {-13720693, 2639453, -24237460, -7406481, 9494427,
     -5774029, -6554551, -15960994, -2449256, -14291300},
    {-3099351, 10324967, -2241613, 7453183, -5446979,
     -2735503, -13812022, -16236442, -32461234, -12290683},
};

// Incremental sliding windows (left to right)
// Based on Roberto Maria Avanzi[2005]
typedef struct {
    i16 next_index; // position of the next signed digit
    i8  next_digit; // next signed digit (odd number below 2^window_width)
    u8  next_check; // point at which we must check for a new window
} slide_ctx;

static void slide_init(slide_ctx *ctx, const u8 scalar[32])
{
    // scalar is guaranteed to be below L, either because we checked (s),
    // or because we reduced it modulo L (h_ram). L is under 2^253, so
    // so bits 253 to 255 are guaranteed to be zero. No need to test them.
    //
    // Note however that L is very close to 2^252, so bit 252 is almost
    // always zero.  If we were to start at bit 251, the tests wouldn't
    // catch the off-by-one error (constructing one that does would be
    // prohibitively expensive).
    //
    // We should still check bit 252, though.
    int i = 252;
    while (i > 0 && scalar_bit(scalar, i) == 0) {
        i--;
    }
    ctx->next_check = (u8)(i + 1);
    ctx->next_index = -1;
    ctx->next_digit = -1;
}

static int slide_step(slide_ctx *ctx, int width, int i, const u8 scalar[32])
{
    if (i == ctx->next_check) {
        if (scalar_bit(scalar, i) == scalar_bit(scalar, i - 1)) {
            ctx->next_check--;
        } else {
            // compute digit of next window
            int w = MIN(width, i + 1);
            int v = -(scalar_bit(scalar, i) << (w-1));
            FOR_T (int, j, 0, w-1) {
                v += scalar_bit(scalar, i-(w-1)+j) << j;
            }
            v += scalar_bit(scalar, i-w);
            int lsb = v & (~v + 1);            // smallest bit of v
            int s   = (   ((lsb & 0xAA) != 0)  // log2(lsb)
                       | (((lsb & 0xCC) != 0) << 1)
                       | (((lsb & 0xF0) != 0) << 2));
            ctx->next_index  = (i16)(i-(w-1)+s);
            ctx->next_digit  = (i8) (v >> s   );
            ctx->next_check -= w;
        }
    }
    return i == ctx->next_index ? ctx->next_digit: 0;
}


#define P_W_WIDTH 3 // Affects the size of the stack
#define B_W_WIDTH 5 // Affects the size of the binary
#define P_W_SIZE  (1<<(P_W_WIDTH-2))
#define B_W_SIZE  (1<<(B_W_WIDTH-2))

// Variable time! Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_double_scalarmult_vartime(ge *P, const u8 p[32], const u8 b[32])
{
    // cache P window for addition
#if defined(CONFIG_MODULE_CRYPTO_CURVE25519_STACK)
    ge_cached cP[P_W_SIZE];
    ge tmp;
#elif defined(CONFIG_MODULE_CRYPTO_CURVE25519_STATIC)
    static ge_cached cP[P_W_SIZE];
    static ge tmp;
#endif
    {
        ge P2;
        ge_double(&P2, P, &tmp);
        ge_cache(&cP[0], P);
        FOR (i, 0, (P_W_SIZE)-1) {
            ge_add(&tmp, &P2, &cP[i]);
            ge_cache(&cP[i+1], &tmp);
        }
    }

    // Merged double and add ladder, fused with sliding
    slide_ctx p_slide;  slide_init(&p_slide, p);
    slide_ctx b_slide;  slide_init(&b_slide, b);
    int i = MAX(p_slide.next_check, b_slide.next_check);
    ge *sum = P;
    ge_zero(sum);
    while (i >= 0) {
        ge_double(sum, sum, &tmp);
        int p_digit = slide_step(&p_slide, P_W_WIDTH, i, p);
        int b_digit = slide_step(&b_slide, B_W_WIDTH, i, b);
        if (p_digit > 0) { ge_add(sum, sum, &cP[ p_digit / 2]); }
        if (p_digit < 0) { ge_sub(sum, sum, &cP[-p_digit / 2]); }
        fe t1, t2;
        if (b_digit > 0) { ge_madd(sum, sum,
                                   window_Yp[ b_digit / 2],
                                   window_Ym[ b_digit / 2],
                                   window_T2[ b_digit / 2], t1, t2); }
        if (b_digit < 0) { ge_msub(sum, sum,
                                   window_Yp[-b_digit / 2],
                                   window_Ym[-b_digit / 2],
                                   window_T2[-b_digit / 2], t1, t2); }
        i--;
    }
}

// 5-bit signed comb in cached format (Niels coordinates, Z=1)
static const fe comb_Yp[16] = {
    {2615675, 9989699, 17617367, -13953520, -8802803,
     1447286, -8909978, -270892, -12199203, -11617247},
    {-1271192, 4785266, -29856067, -6036322, -10435381,
     15493337, 20321440, -6036064, 15902131, 13420909},
    {-26170888, -12891603, 9568996, -6197816, 26424622,
     16308973, -4518568, -3771275, -15522557, 3991142},
    {-25875044, 1958396, 19442242, -9809943, -26099408,
     -18589, -30794750, -14100910, 4971028, -10535388},
    {-13896937, -7357727, -12131124, 617289, -33188817,
     10080542, 6402555, 10779157, 1176712, 2472642},
    {71503, 12662254, -17008072, -8370006, 23408384,
     -12897959, 32287612, 11241906, -16724175, 15336924},
    {27397666, 4059848, 23573959, 8868915, -10602416,
     -10456346, -22812831, -9666299, 31810345, -2695469},
    {-3418193, -694531, 2320482, -11850408, -1981947,
     -9606132, 23743894, 3933038, -25004889, -4478918},
    {-4448372, 5537982, -4805580, 14016777, 15544316,
     16039459, -7143453, -8003716, -21904564, 8443777},
    {32495180, 15749868, 2195406, -15542321, -3213890,
     -4030779, -2915317, 12751449, -1872493, 11926798},
    {26779741, 12553580, -24344000, -4071926, -19447556,
     -13464636, 21989468, 7826656, -17344881, 10055954},
    {5848288, -1639207, -10452929, -11760637, 6484174,
     -5895268, -11561603, 587105, -19220796, 14378222},
    {32050187, 12536702, 9206308, -10016828, -13333241,
     -4276403, -24225594, 14562479, -31803624, -9967812},
    {23536033, -6219361, 199701, 4574817, 30045793,
     7163081, -2244033, 883497, 10960746, -14779481},
    {-8143354, -11558749, 15772067, 14293390, 5914956,
     -16702904, -7410985, 7536196, 6155087, 16571424},
    {6211591, -11166015, 24568352, 2768318, -10822221,
     11922793, 33211827, 3852290, -13160369, -8855385},
};
static const fe comb_Ym[16] = {
    {8873912, 14981221, 13714139, 6923085, 25481101,
     4243739, 4646647, -203847, 9015725, -16205935},
    {-1827892, 15407265, 2351140, -11810728, 28403158,
     -1487103, -15057287, -4656433, -3780118, -1145998},
    {-30623162, -11845055, -11327147, -16008347, 17564978,
     -1449578, -20580262, 14113978, 29643661, 15580734},
    {-15109423, 13348938, -14756006, 14132355, 30481360,
     1830723, -240510, 9371801, -13907882, 8024264},
    {25119567, 5628696, 10185251, -9279452, 683770,
     -14523112, -7982879, -16450545, 1431333, -13253541},
    {-8390493, 1276691, 19008763, -12736675, -9249429,
     -12526388, 17434195, -13761261, 18962694, -1227728},
    {26361856, -12366343, 8941415, 15163068, 7069802,
     -7240693, -18656349, 8167008, 31106064, -1670658},
    {-5677136, -11012483, -1246680, -6422709, 14772010,
     1829629, -11724154, -15914279, -18177362, 1301444},
    {937094, 12383516, -22597284, 7580462, -18767748,
     13813292, -2323566, 13503298, 11510849, -10561992},
    {28028043, 14715827, -6558532, -1773240, 27563607,
     -9374554, 3201863, 8865591, -16953001, 7659464},
    {13628467, 5701368, 4674031, 11935670, 11461401,
     10699118, 31846435, -114971, -8269924, -14777505},
    {-22124018, -12859127, 11966893, 1617732, 30972446,
     -14350095, -21822286, 8369862, -29443219, -15378798},
    {290131, -471434, 8840522, -2654851, 25963762,
     -11578288, -7227978, 13847103, 30641797, 6003514},
    {-23547482, -11475166, -11913550, 9374455, 22813401,
     -5707910, 26635288, 9199956, 20574690, 2061147},
    {9715324, 7036821, -17981446, -11505533, 26555178,
     -3571571, 5697062, -14128022, 2795223, 9694380},
    {14864569, -6319076, -3080, -8151104, 4994948,
     -1572144, -41927, 9269803, 13881712, -13439497},
};
static const fe comb_T2[16] = {
    {-18494317, 2686822, 18449263, -13905325, 5966562,
     -3368714, 2738304, -8583315, 15987143, 12180258},
    {-33336513, -13705917, -18473364, -5039204, -4268481,
     -4136039, -8192211, -2935105, -19354402, 5995895},
    {-19753139, -1729018, 21880604, 13471713, 28315373,
     -8530159, -17492688, 11730577, -8790216, 3942124},
    {17278020, 3905045, 29577748, 11151940, 18451761,
     -6801382, 31480073, -13819665, 26308905, 10868496},
    {26937294, 3313561, 28601532, -3497112, -22814130,
     11073654, 8956359, -16757370, 13465868, 16623983},
    {-5468054, 6059101, -31275300, 2469124, 26532937,
     8152142, 6423741, -11427054, -15537747, -10938247},
    {-11303505, -9659620, -12354748, -9331434, 19501116,
     -9146390, -841918, -5315657, 8903828, 8839982},
    {16603354, -215859, 1591180, 3775832, -705596,
     -13913449, 26574704, 14963118, 19649719, 6562441},
    {33188866, -12232360, -24929148, -6133828, 21818432,
     11040754, -3041582, -3524558, -29364727, -10264096},
    {-20704194, -12560423, -1235774, -785473, 13240395,
     4831780, -472624, -3796899, 25480903, -15422283},
    {-2204347, -16313180, -21388048, 7520851, -8697745,
     -14460961, 20894017, 12210317, -475249, -2319102},
    {-16407882, 4940236, -21194947, 10781753, 22248400,
     14425368, 14866511, -7552907, 12148703, -7885797},
    {16376744, 15908865, -30663553, 4663134, -30882819,
     -10105163, 19294784, -10800440, -33259252, 2563437},
    {30208741, 11594088, -15145888, 15073872, 5279309,
     -9651774, 8273234, 4796404, -31270809, -13316433},
    {-17802574, 14455251, 27149077, -7832700, -29163160,
     -7246767, 17498491, -4216079, 31788733, -14027536},
    {-25233439, -9389070, -6618212, -3268087, -521386,
     -7350198, 21035059, -14970947, 25910190, 11122681},
};

static void ge_scalarmult_base(ge *p, const u8 scalar[32])
{
    // 5-bits signed comb, from Mike Hamburg's
    // Fast and compact elliptic-curve cryptography (2012)
    static const u8 half_mod_L[32] = { // 1 / 2 modulo L
        0xf7, 0xe9, 0x7a, 0x2e, 0x8d, 0x31, 0x09, 0x2c,
        0x6b, 0xce, 0x7b, 0x51, 0xef, 0x7c, 0x6f, 0x0a,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    };
    static const u8 half_ones[32] = { // (2^255 - 1) / 2 modulo L
        0x42, 0x9a, 0xa3, 0xba, 0x23, 0xa5, 0xbf, 0xcb,
        0x11, 0x5b, 0x9d, 0xc5, 0x74, 0x95, 0xf3, 0xb6,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07,
    };
    // All bits set form: 1 means 1, 0 means -1
    u8 s_scalar[32];
    mul_add(s_scalar, scalar, half_mod_L, half_ones);

    // Double and add ladder
    fe yp, ym, t2, n2, a; // temporaries for addition
    ge dbl;               // temporary for doubling
    ge_zero(p);
    for (int i = 50; i >= 0; i--) {
        if (i < 50) {
            ge_double(p, p, &dbl);
        }
        fe_1(yp);
        fe_1(ym);
        fe_0(t2);
        u8 teeth = (u8)((scalar_bit(s_scalar, i)           ) +
                        (scalar_bit(s_scalar, i +  51) << 1) +
                        (scalar_bit(s_scalar, i + 102) << 2) +
                        (scalar_bit(s_scalar, i + 153) << 3) +
                        (scalar_bit(s_scalar, i + 204) << 4));
        u8 high  = teeth >> 4;
        u8 index = (teeth ^ (high - 1)) & 15;
        FOR (j, 0, 16) {
            i32 select = 1 & (((j ^ index) - 1) >> 8);
            fe_ccopy(yp, comb_Yp[j], select);
            fe_ccopy(ym, comb_Ym[j], select);
            fe_ccopy(t2, comb_T2[j], select);
        }

        fe_neg(n2, t2);
        fe_cswap(t2, n2, high);
        fe_cswap(yp, ym, high);
        ge_madd(p, p, ym, yp, n2, a, t2); // reuse t2 as temporary
    }
    WIPE_CTX(&dbl);
    WIPE_BUFFER(yp);  WIPE_BUFFER(t2);  WIPE_BUFFER(a);
    WIPE_BUFFER(ym);  WIPE_BUFFER(n2);
    WIPE_BUFFER(s_scalar);
}

void crypto_sign_public_key(u8 public_key[32], const u8 secret_key[32])
{
    u8 a[64];
    HASH(a, secret_key, 32);
    trim_scalar(a);
    ge A;
    ge_scalarmult_base(&A, a);
    ge_tobytes(public_key, &A);
    WIPE_BUFFER(a);
    WIPE_CTX(&A);
}

void crypto_sign_init_first_pass(crypto_sign_ctx *ctx,
                                 const u8 secret_key[32],
                                 const u8 public_key[32])
{
    u8 *a      = ctx->buf;
    u8 *prefix = ctx->buf + 32;

    HASH(a, secret_key, 32);
    trim_scalar(a);

    if (public_key == 0) {
        crypto_sign_public_key(ctx->pk, secret_key);
    } else {
        FOR (i, 0, 32) {
            ctx->pk[i] = public_key[i];
        }
    }

    // Constructs the "random" nonce from the secret key and message.
    // An actual random number would work just fine, and would save us
    // the trouble of hashing the message twice.  If we did that
    // however, the user could fuck it up and reuse the nonce.
    HASH_INIT  (&ctx->hash);
    HASH_UPDATE(&ctx->hash, prefix , 32);
}

void crypto_sign_update(crypto_sign_ctx *ctx, const u8 *msg, size_t msg_size)
{
    HASH_UPDATE(&ctx->hash, msg, msg_size);
}

void crypto_sign_init_second_pass(crypto_sign_ctx *ctx)
{
    u8 *r        = ctx->buf + 32;
    u8 *half_sig = ctx->buf + 64;
    HASH_FINAL(&ctx->hash, r);
    reduce(r);

    // first half of the signature = "random" nonce times the base point
    ge R;
    ge_scalarmult_base(&R, r);
    ge_tobytes(half_sig, &R);
    WIPE_CTX(&R);

    // Hash R, the public key, and the message together.
    // It cannot be done in parallel with the first hash.
    HASH_INIT  (&ctx->hash);
    HASH_UPDATE(&ctx->hash, half_sig, 32);
    HASH_UPDATE(&ctx->hash, ctx->pk , 32);
}

void crypto_sign_final(crypto_sign_ctx *ctx, u8 signature[64])
{
    u8 *a        = ctx->buf;
    u8 *r        = ctx->buf + 32;
    u8 *half_sig = ctx->buf + 64;
    u8 h_ram[64];
    HASH_FINAL(&ctx->hash, h_ram);
    reduce(h_ram);
    FOR (i, 0, 32) {
        signature[i] = half_sig[i];
    }
    mul_add(signature + 32, h_ram, a, r); // s = h_ram * a + r
    WIPE_CTX(ctx);
    WIPE_BUFFER(h_ram);
}

void crypto_sign(u8        signature[64],
                 const u8  secret_key[32],
                 const u8  public_key[32],
                 const u8 *message, size_t message_size)
{
    crypto_sign_ctx ctx;
    crypto_sign_init_first_pass (&ctx, secret_key, public_key);
    crypto_sign_update          (&ctx, message, message_size);
    crypto_sign_init_second_pass(&ctx);
    crypto_sign_update          (&ctx, message, message_size);
    crypto_sign_final           (&ctx, signature);
}

void crypto_check_init(crypto_check_ctx *ctx,
                      const u8 signature[64],
                      const u8 public_key[32])
{
    FOR (i, 0, 64) { ctx->sig[i] = signature [i]; }
    FOR (i, 0, 32) { ctx->pk [i] = public_key[i]; }
    HASH_INIT  (&ctx->hash);
    HASH_UPDATE(&ctx->hash, signature , 32);
    HASH_UPDATE(&ctx->hash, public_key, 32);
}

void crypto_check_update(crypto_check_ctx *ctx, const u8 *msg, size_t msg_size)
{
    HASH_UPDATE(&ctx->hash, msg , msg_size);
}

int crypto_check_final(crypto_check_ctx *ctx)
{
    ge A;
    u8 *h_ram   = ctx->pk; // save stack space
    u8 *R_check = ctx->pk; // save stack space
    u8 *R       = ctx->sig;                      // R
    u8 *s       = ctx->sig + 32;                 // s
    ge *diff    = &A;                            // -A is overwritten...
    if (ge_frombytes_neg_vartime(&A, ctx->pk) ||
        is_above_L(s)) { // prevent s malleability
        return -1;
    }
    {
        u8 tmp[64];
        HASH_FINAL(&ctx->hash, tmp);
        reduce(tmp);
        FOR (i, 0, 32) { // the extra copy saves 32 bytes of stack
            h_ram[i] = tmp[i];
        }
    }
    ge_double_scalarmult_vartime(&A, h_ram, s);  // ...here
    ge_tobytes(R_check, diff);                   // R_check = s*B - h_ram*A
    return crypto_verify32(R, R_check);          // R == R_check ? OK : fail
    // No secret, no wipe
}

int crypto_check(const u8  signature[64],
                 const u8  public_key[32],
                 const u8 *message, size_t message_size)
{
#if defined(CONFIG_MODULE_CRYPTO_CURVE25519_STACK)
    crypto_check_ctx ctx;
#elif defined(CONFIG_MODULE_CRYPTO_CURVE25519_STATIC)
    static crypto_check_ctx ctx;
#endif
    crypto_check_init(&ctx, signature, public_key);
    crypto_check_update(&ctx, message, message_size);
    return crypto_check_final(&ctx);
}
