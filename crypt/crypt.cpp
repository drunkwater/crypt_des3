// crypt.cpp : Defines the entry point for the application.
//

#include "crypt.h"

/*--------------------------------------------------------------------------------
# @filename           :  main.c
# @author             :  Copyright (C) Church.Zhong
# @date               :  Thu May  3 17:03:28 HKT 2018
# @function           :
# @see                :
# @require            :
--------------------------------------------------------------------------------*/

/* https://github.com/ivanrad/getline */
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
    char c, *cur_pos, *new_lineptr;
    size_t new_lineptr_len;

    if (lineptr == NULL || n == NULL || stream == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (*lineptr == NULL) {
        *n = 128; /* init len */
        if ((*lineptr = (char *)malloc(*n)) == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }

    cur_pos = *lineptr;
    for (;;) {
        c = getc(stream);

        if (ferror(stream) || (c == EOF && cur_pos == *lineptr))
            return -1;

        if (c == EOF)
            break;

        if ((*lineptr + *n - cur_pos) < 2) {
            if (SSIZE_MAX / 2 < *n) {
#ifdef EOVERFLOW
                errno = EOVERFLOW;
#else
                errno = ERANGE; /* no EOVERFLOW defined */
#endif
                return -1;
            }
            new_lineptr_len = *n * 2;

            if ((new_lineptr = (char *)realloc(*lineptr, new_lineptr_len)) == NULL) {
                errno = ENOMEM;
                return -1;
            }
            cur_pos = new_lineptr + (cur_pos - *lineptr);
            *lineptr = new_lineptr;
            *n = new_lineptr_len;
        }

        *cur_pos++ = c;

        if (c == delim)
            break;
    }

    *cur_pos = '\0';
    return (ssize_t)(cur_pos - *lineptr);
}

ssize_t _getline(char **lineptr, size_t *n, FILE *stream) {
    return getdelim(lineptr, n, '\n', stream);
}





const char *version = MACRO2STR(VER_CONS(SW_VER_MAJOR, SW_VER_MINOR, SW_VER_REVISION, SW_VER_BUILD_ID));
static char *programname;


const unsigned char cryptkey[24] =
{
};

int des3_crypt(unsigned char *in, unsigned char *out, int in_len, const unsigned char *key, int enc /*= 1 encrypt*/)
{
	unsigned char iv[8] = {};
	unsigned char *buf = in;
	int bufsize = (0 == enc) ? (in_len) : ((in_len / 8 + 1) * 8);
	int padsize = bufsize - in_len;
	int outsize = (0 == enc) ? (bufsize - padsize) : (bufsize);

	C_DEBUG("enc=%d, in_len=%d\n", enc, in_len);

	/* sanity check */
	if (!in || !out || !key)
	{
		fprintf(stderr, "Error: invalid arguments!\n");
		return -1;
	}
	if (MAXBUFSIZE < bufsize)
	{
		fprintf(stderr, "Error: input too long!\n");
		return -1;
	}
	if (0 != enc)
	{
		memset(buf + in_len, padsize, padsize);
		memcpy(buf, in, in_len);
	}

	mbedtls_des3_context des3;
	mbedtls_des3_init(&des3);
	if (0 == enc)
	{
		mbedtls_des3_set3key_dec(&des3, key);
	}
	else
	{
		mbedtls_des3_set3key_enc(&des3, key);
	}
	int ok = mbedtls_des3_crypt_cbc(&des3, (0 == enc) ? MBEDTLS_DES_DECRYPT : MBEDTLS_DES_ENCRYPT, bufsize, iv, buf, out);
	C_DEBUG("ok=%d\n", ok);
	mbedtls_des3_free(&des3);

	if (0 == enc)
	{
		int i = 0;
		// get pad size
		padsize = out[bufsize - 1];
		if (8 < padsize)
		{
			//It's impossible
			fprintf(stderr, "Error: invalid padsize=%d!\n", padsize);
			return -1;
		}
		// check for correct decryption
		for (i = 0; i<padsize; ++i)
		{
			if (out[bufsize - i - 1] != padsize)
			{
				//It's impossible
				fprintf(stderr, "Error: check padsize failed!\n");
				return -1;
			}
		}
		outsize = (bufsize - padsize);
		// bad, but this was previous workflow/behavior
		out[outsize] = '\0';
	}

	return (outsize);
}




/*
** Translation Table as described in RFC1113
*/
static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** Translation Table to decode (created by author)
*/
static const char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
static void encodeblock(unsigned char in[3], unsigned char out[4], int len)
{
	out[0] = cb64[in[0] >> 2];
	out[1] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
	out[2] = (unsigned char)(len > 1 ? cb64[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)] : '=');
	out[3] = (unsigned char)(len > 2 ? cb64[in[2] & 0x3f] : '=');
}

/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
static void decodeblock(unsigned char in[4], unsigned char out[3])
{
	out[0] = (unsigned char)(in[0] << 2 | in[1] >> 4);
	out[1] = (unsigned char)(in[1] << 4 | in[2] >> 2);
	out[2] = (unsigned char)(((in[2] << 6) & 0xc0) | in[3]);
}

void base64_encode(const unsigned char *buf, int in_len, unsigned char *ret)
{
	unsigned char in[3], out[4];
	int i, len;
	int pos = 0;

	while (pos < in_len) {
		len = 0;
		for (i = 0; i < 3; i++) {
			if (pos < in_len) {
				in[i] = buf[pos++];
				len++;
			}
			else {
				in[i] = 0;
			}
		}
		if (len) {
			encodeblock(in, out, len);
			for (i = 0; i < 4; i++) {
				*ret++ = out[i];
			}
		}
	}
	*ret = '\0';
}

int base64_decode(const unsigned char *buf, int in_len, unsigned char *ret)
{
	unsigned char in[4], out[3], v;
	int i, len;
	int pos = 0, out_pos = 0;

	while (pos < in_len) {
		for (len = 0, i = 0; i < 4 && pos < in_len; i++) {
			v = 0;
			while (pos < in_len && v == 0) {
				v = buf[pos++];
				v = (unsigned char)((v < 43 || v > 122) ? 0 : cd64[v - 43]);
				if (v) {
					v = (unsigned char)((v == '$') ? 0 : v - 61);
				}
			}
			if (pos < in_len || (v != 0)) {
				len++;
				if (v) {
					in[i] = (unsigned char)(v - 1);
				}
			}
			else {
				in[i] = 0;
			}
		}
		if (len) {
			decodeblock(in, out);
			for (i = 0; i < len - 1; i++) {
				ret[out_pos++] = out[i];
			}
		}
	}

	return out_pos;
}

#define ENCRYPTED_PASS_START "{\""
#define ENCRYPTED_PASS_END "\"}"
#define CONFIG_FILE_EXTENSION	".cfg"
#define ENCRYPTED_CONFIG_FILE_EXTENSION	".cfx"


/*--------------------------------------------------------------------------------*/

static int EncryptConfigFile(char *inFilename, char *outFilename)
{
	/* sanity check */
	FILE *ofp = fopen(outFilename, "wb");
	if (NULL==ofp)
	{
		fprintf(stderr, "Error: fopen %s failed!\n", outFilename);
		return -1;
	}

    FILE *ifp = fopen(inFilename, "r");
	if (NULL==ifp)
	{
		fclose(ofp);
		fprintf(stderr, "Error: fopen %s failed!\n", outFilename);
		return -1;
	}

    char *line = NULL;
    size_t len = 0;
    int read;

	unsigned char cipher[MAXBUFSIZE] = { 0 };
	unsigned char plain[MAXBUFSIZE] = { 0 };
	int plainlen = 0;
	int cipherlen = 0;
	unsigned char bytes[4] = { 0 };
    while ((read = _getline(&line, &len, ifp)) != -1)
	{
        //fprintf(stdout, "Retrieved line of length %u : %s", read, line);
		plainlen = read;
		memcpy(plain, line, plainlen);

		cipherlen = des3_crypt(plain, cipher, plainlen, cryptkey, 1);
		//fprintf(stdout, "cipherlen=%d\n", cipherlen);
		int length = htonl(cipherlen);
		bytes[0] = (length >> 24) & 0xFF;
		bytes[1] = (length >> 16) & 0xFF;
		bytes[2] = (length >> 8) & 0xFF;
		bytes[3] = length & 0xFF;
		(void)fwrite(bytes, sizeof(bytes), 1, ofp);
		(void)fwrite((void *)cipher, sizeof(cipher[0]), cipherlen, ofp);
    }
	fclose(ifp);
    fclose(ofp);
    if (line)
	{
        free(line);
		line = NULL;
    }

	return 0;
}

static int DecryptConfigFile(char *inFilename, char *outFilename)
{
	/* sanity check */
	FILE *ofp = fopen(outFilename, "wb");
	if (NULL==ofp)
	{
		fprintf(stderr, "Error: fopen %s failed!\n", outFilename);
		return -1;
	}

	FILE *ifp = fopen(inFilename, "rb");
	if (NULL==ifp)
	{
		fclose(ofp);
		fprintf(stderr, "Error: fopen %s failed!\n", outFilename);
		return -1;
	}

	unsigned char cipher[MAXBUFSIZE] = { 0 };
	unsigned char plain[MAXBUFSIZE] = { 0 };
	int plainlen = 0;

	int offset = 0;
	int blockLength = 0;
	unsigned char bytes[4] = {0};
	int wordSize = sizeof bytes;

	fseek(ifp, 0L, SEEK_END);
	unsigned long size = ftell(ifp);
	fseek(ifp, 0L, SEEK_SET);

	while (offset < size)
	{
		(void)fread(bytes, sizeof(bytes), 1, ifp);
		blockLength = (bytes[0] << 24)|(bytes[1] << 16)|(bytes[2] << 8)|(bytes[3]);
		blockLength = ntohl(blockLength);
		//fprintf(stdout, "blockLength=%d\n", blockLength);
		offset += wordSize;

		(void)fread(cipher, blockLength, 1, ifp);
		plainlen = des3_crypt(cipher, plain, blockLength, cryptkey, 0);
		if (0 < plainlen)
		{
			for (int i = 0; i < plainlen; i++)
			{
				if (0 != plain[i])
				{
					(void)fwrite((void *)&plain[i], sizeof(plain[i]), 1, ofp);
				}
			}
		}
		offset += blockLength;
	}
	fclose(ifp);
	fclose(ofp);

	return 0;
}

const char *get_filename_extension(const char *filename)
{
	/* sanity check */
	if (NULL == filename)
	{
		return "";
	}
	const char *dot = strrchr(filename, '.');
	if (!dot || dot == filename)
	{
		return "";
	}
	return dot;
}

void usage(void)
{
	fprintf(stdout,
		"Usage: %s [OPTION]... [-s] string \n"
		"   or: %s [OPTION]... [-d] path \n"
		"   or: %s [OPTION]... [-e] path \n"
		"\n"
		"Mandatory arguments to long options are mandatory for short options too. \n"
		"  -s, --string 	 given string to encrypt, max length is 128 \n"
		"  -m, --method      string encrypt method, 0=MD5(default), 1=DES3+BASE64 \n"
		"  -d, --decrypt     decrypt the given encrypted config file to plain *.cfg file \n"
		"  -e, --encrypt     encrypt the given plain config file to encrypted *.cfx file \n\n",
		programname, programname, programname);

	fprintf(stdout, "%s %s\n", programname, version);
}

//required_argument: --opt value or --opt=value or -p value;
//optional_argument: --opt=value -pvalue;
//#define church_debug 1
static struct option longopts[] =
{
	{ "string",                  required_argument, 0, 's' },
	{ "decrypt",                 required_argument, 0, 'd' },
	{ "encrypt",                 required_argument, 0, 'e' },
	{ "method",                  optional_argument, 0, 'm' },
#if church_debug
	{ "opt",                     optional_argument, 0, 'i' },
	{ "church",                  required_argument, 0,  8 },
#endif
	{ "version",                 no_argument,       0, 'v' },
	{ "help",                    no_argument,       0, 'h' },
	{ 0,                         0,                 0,  0 }
};
#if church_debug
const char *optstring = "vhs:d:e:m::i::";
#else
const char *optstring = "vhs:d:e:m::";
#endif

int main(int argc, char **argv, char **env)
{
	int optc;
	int option_index = 0;
	int h = 0, v = 0;

	/* sanity check */
	programname = argv[0];
	int work = 0;
	int method = 0;/* 0=MD5; 1=DES3+BASE64 */
	char *p = NULL;

	while ((optc = getopt_long(argc, argv, optstring, longopts, &option_index)) != EOF)
	{
		//fprintf (stderr, "option_index=%d, optind=%d \n", option_index, optind);
		switch (optc)
		{
		case 'v':
			v = 1;
			break;
		case 'h':
			h = 1;
			break;

		case 's':
		{
			if (0 == work && NULL == p)
			{
				p = argv[(optind - 1)];
				work = 1;
			}
			break;
		}

		case 'd':
		{
			if (0 == work && NULL == p)
			{
				p = argv[(optind - 1)];
				work = 2;
			}
			break;
		}

		case 'e':
		{
			if (0 == work && NULL == p)
			{
				p = argv[(optind - 1)];
				work = 3;
			}
			break;
		}

		case 'm':
		{
			if (1 != work)
			{
				fprintf(stdout, "ignore option '-m%s'\n", optarg ? optarg : "");
				break;
			}

			if (optarg)
			{
				//C_DEBUG ("optarg=%s\n", optarg);
				method = strtoul(optarg, NULL, 10);
				if (0 != method && 1 != method)
				{
					fprintf(stderr, "Error: invalid method=%d\n", method);
					usage();
					exit(0);
				}
				//C_DEBUG ("method=0x%x\n", method);
			}
			break;
		}

#if church_debug
		case 'i':
		{
			if (optarg)
			{
				C_DEBUG("optarg=%s\n", optarg);
				C_DEBUG("int=0x%x\n", strtoul(optarg, NULL, 10));
			}
			break;
		}

		case 8:
			C_DEBUG("church=%d \n", atoi(optarg));
			break;
#endif

		case '?':
		default:
			break;
		}
	}

	if (v)
	{
		/* Print version number.  */
		fprintf(stderr, "%s\n", version);
		if (!h)
			exit(0);
	}

	if (h)
	{
		/* Print help info and exit.  */
		usage();
		exit(0);
	}

	//C_DEBUG("work=%d, optind=%d, argc=%d, method=%d, p=%s \n", work, optind, argc, method, p?p:"NULL");
	if (0 == work || optind < argc || (1 == work && argc < 4) || (1<work && argc < 3))
	{
		usage();
		exit(1);
	}

	size_t length = strlen(p);
	const char *ext = get_filename_extension(p);
	char out[PATH_MAX] = { 0 };

	switch (work)
	{
	case 1:
	{
		if (0 == method)
		{
			const char salt[64] = "";/*fixed salt */
			char *cipher = crypt(p, salt);
			fprintf(stdout, "MD5 Encrypt string=%s To %s \n", p, cipher);
		}
		else
		{
			unsigned char cipher[MAXBUFSIZE] = { 0 };
			unsigned char encode[MAXBUFSIZE] = { 0 };
			int cipherlen = des3_crypt((unsigned char *)p, cipher, (int)strlen(p), cryptkey, 1);
			base64_encode(cipher, cipherlen, encode);
			snprintf((char *)cipher, sizeof(cipher), "%s%s%s", ENCRYPTED_PASS_START, encode, ENCRYPTED_PASS_END);
			fprintf(stdout, "DES3+BASE64 Encrypt string=%s To %s \n", p, cipher);
		}
		break;
	}
	case 2:
	{
		if (0 == strncmp(ext, CONFIG_FILE_EXTENSION, strlen(CONFIG_FILE_EXTENSION)))
		{
			fprintf(stdout, "ignore plain file=%s \n", p ? p : "");
		}
		else if (0 == strncmp(ext, ENCRYPTED_CONFIG_FILE_EXTENSION, strlen(ENCRYPTED_CONFIG_FILE_EXTENSION)))
		{
			memcpy(out, p, length);
			out[length - 1] = 'g';
			out[length] = '\0';

			fprintf(stdout, "Decrypt file=%s To %s %s!\n", p ? p : "", out, (0==DecryptConfigFile(p, out))?"successfully":"failed");
		}
		else
		{
			fprintf(stdout, "Error: extension of file must be *.cfx! \n");
		}
		break;
	}
	case 3:
	{
		const char *ext = get_filename_extension(p);
		if (0 == strncmp(ext, CONFIG_FILE_EXTENSION, strlen(CONFIG_FILE_EXTENSION)))
		{
			memcpy(out, p, length);
			out[length - 1] = 'x';
			out[length] = '\0';

			fprintf(stdout, "Encrypt file=%s To %s %s!\n", p ? p : "", out, (0==EncryptConfigFile(p, out))?"successfully":"failed");
		}
		else if (0 == strncmp(ext, ENCRYPTED_CONFIG_FILE_EXTENSION, strlen(ENCRYPTED_CONFIG_FILE_EXTENSION)))
		{
			fprintf(stdout, "ignore encrypted file=%s \n", p ? p : "");
		}
		else
		{
			fprintf(stdout, "Error: extension of file must be *.cfg! \n");
		}
		break;
	}
	default:
		fprintf(stdout, "Error: unknown argument! \n");
		break;
	}

	return 0;
}

/* valgrind --tool=memcheck --leak-check=full ./app_elf */


