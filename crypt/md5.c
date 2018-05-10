#include "md5.h"

//http://people.csail.mit.edu/rivest/Md5.c

/* typedef a 32 bit type */
typedef unsigned int UINT4;


/* Data structure for MD5 (Message Digest) computation */
typedef struct {
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
  UINT4 buf[4];                                    /* scratch buffer */
  unsigned char in[64];                              /* input buffer */
  unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;

static void Transform(UINT4 *buf, UINT4 *in);

static unsigned char PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (MD5_CTX *mdContext)
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen)
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (MD5_CTX *mdContext)
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  MD5Update (mdContext, PADDING, padLen);

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (UINT4 *buf, UINT4 *in)
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
  FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
  FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */
  FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */
  FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */
  FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */
  FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */
  FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
  GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
  GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */
  GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
  GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */
  GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
  GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
  GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
  HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */
  HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
  HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */
  HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
  HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
  HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */
  HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
  II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
  II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
  II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
  II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
  II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
  II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */
  II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}


static const char itoa64[64] = {
	'.', '/', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9',
	'A', 'B', 'C', 'D', 'E', 'F',
	'G', 'H', 'I', 'J', 'K', 'L',
	'M', 'N', 'O', 'P', 'Q', 'R',
	'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p',
	'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z' };

void _crypt_to64(char *s, unsigned long v, int n)
{
	/* sanity check */
	int i = 0;
	while (--n >= 0) {
		s[i++] = (char)itoa64[v & 0x3f];
		v >>= 6;
	}
}


/// <summary>This method encrypt the given string with the salt indicated, using MD5 Algorithm</summary>
/// <param name="pwd">The password to be encrypted.</param>
/// <param name="magicSalt"> The magic and salt.</param>
/// <returns>The encrypted password.</returns>
int Encrypt(unsigned char *pwd, unsigned char *magicSalt, unsigned char *out)
{
	/* sanity check */

	MD5_CTX MDp1;
	MD5_CTX MDp2;
	char *magic = "$1$";

	if (NULL==pwd || NULL==magicSalt || NULL==out)
	{
		fprintf(stderr, "null pointer!");
		return -1;
	}

	int magicSaltLen = (int)strlen(magicSalt);
	int magicLength = (int)strlen(magic);
	int saltLength = magicSaltLen - magicLength;
	int pwdLength = (int)strlen(pwd);

	if (3>magicSaltLen || 
		!('$'==magicSalt[0] && '1'==magicSalt[1] && '$'==magicSalt[2]))
	{
		fprintf(stderr, "invalid magicSalt!");
		return -1;
	}

	char salt[64] = {0};
	memcpy(salt, magicSalt+3, magicSaltLen-3);

	MD5Init(&MDp1);
	MD5Update(&MDp1, (pwd), pwdLength);
	MD5Update(&MDp1, (magic), magicLength);
	MD5Update(&MDp1, (salt), saltLength);
	MD5Init(&MDp2);
	MD5Update(&MDp2, (pwd), pwdLength);
	MD5Update(&MDp2, (salt), saltLength);
	MD5Update(&MDp2, (pwd), pwdLength);
	MD5Final(&MDp2);
	int i, j, pl;
	for (j = 0 ; j < 16 ; j++)
		MDp1.digest[j] = MDp2.digest[j];
	for (pl = pwdLength ; pl > 0 ; pl -= 16)
		MD5Update(&MDp1, MDp1.digest, ((pl > 16) ? 16 : pl));
	for (i = 0 ; i < 16 ; i++)
		MDp1.digest[i] = 0x00;
	for (i = pwdLength ; (i) ; i >>= 1)
		if ((i & 1))
			MD5Update(&MDp1, MDp1.digest, 1);
		else
			MD5Update(&MDp1, (pwd), 1);
	MD5Final(&MDp1);
	for (i = 0 ; i < 1000 ; i++) {
		MD5Init(&MDp2);
		if ((i & 1))
			MD5Update(&MDp2, (pwd), pwdLength);
		else
			MD5Update(&MDp2, MDp1.digest, 16);
		if ((i % 3))
			MD5Update(&MDp2, (salt), saltLength);
		if ((i % 7))
			MD5Update(&MDp2, (pwd), pwdLength);
		if ((i & 1))
			MD5Update(&MDp2, MDp1.digest, 16);
		else
			MD5Update(&MDp2, (pwd), pwdLength);
		MD5Final(&MDp2);
		for (j = 0 ; j < 16 ; j++)
			MDp1.digest[j] = MDp2.digest[j];
	}
	memcpy(out, magic, magicLength);
	memcpy(out+magicLength, salt, saltLength);
	out[ magicLength + saltLength ] = '$';

	int offset = magicLength+saltLength+1;
	char s[4] = {0};
	UINT4 l;

	l = (UINT4)((MDp1.digest[ 0] << 16) | (MDp1.digest[ 6] << 8) | MDp1.digest[12]);
	_crypt_to64(s, l, 4);
	memcpy(out+offset, s, 4);
	offset+=4;

	l = (UINT4)((MDp1.digest[ 1] << 16) | (MDp1.digest[ 7] << 8) | MDp1.digest[13]);
	_crypt_to64(s, l, 4);
	memcpy(out+offset, s, 4);
	offset+=4;

	l = (UINT4)((MDp1.digest[ 2] << 16) | (MDp1.digest[ 8] << 8) | MDp1.digest[14]);
	_crypt_to64(s, l, 4);
	memcpy(out+offset, s, 4);
	offset+=4;

	l = (UINT4)((MDp1.digest[ 3] << 16) | (MDp1.digest[ 9] << 8) | MDp1.digest[15]);
	_crypt_to64(s, l, 4);
	memcpy(out+offset, s, 4);
	offset+=4;

	l = (UINT4)((MDp1.digest[ 4] << 16) | (MDp1.digest[10] << 8) | MDp1.digest[ 5]);
	_crypt_to64(s, l, 4);
	memcpy(out+offset, s, 4);
	offset+=4;

	l = (UINT4)MDp1.digest[11];
	_crypt_to64(s, l, 2);
	memcpy(out+offset, s, 2);
	offset+=2;

	return 0;
}




static unsigned char buffer[64] = {0};
char *crypt(const char *key, const char *salt)
{
	Encrypt((unsigned char *)key, (unsigned char *)salt, buffer);
	return buffer;
}



//https://en.wikipedia.org/wiki/Crypt_(C)
//$id$salt$encrypted
//   Scheme id     |    Schema   | Len |  Example
//                 |    DES      | 13  |  Kyq4bCxAXJkbg
//     _           |    BSDi     | 19  |  _EQ0.jzhSVeUyoSqLupI
//     1           |    MD5      | 22  |  $1$etNnh7FA$OlM7eljE/B7F1J4XYNnk81
//   2, 2a, 2x, 2y |    bcrypt   | 53  |  $2a$10$VIhIOofSMqgdGlL4wzE//e.77dAQGqntF/1dT7bqCrVtquInWy2qi
//   3             |    NTHASH   | 32  |  $3$$8846f7eaee8fb117ad06bdd830b7586c
//   5             |    SHA-256  | 43  |  $5$9ks3nNEqv31FX.F$gdEoLFsCRsn/WRN3wxUnzfeZLoooVlzeF4WjLomTRFD
//   6             |    SHA-512  | 86  |  $6$qoE2letU$wWPRl.PVczjzeMVgjiA8LLy2nOyZbf7Amj3qLIL978o18gbMySdKZ7uepq9tmMQXxyTIrS12Pln.2Q/6Xscao0
//   md5           | Solaris MD5 | 32  |  $md5,rounds=5000$GUBv0xjJ$$mSwgIswdjlTY0YxV7HBVm0
//   sha1          |PBKDF1(SHA-1)| 37  |  $sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq

//http://sourceforge.net/projects/cryptapi/files/OldFiles/CryptAPI-1.0.zip/download