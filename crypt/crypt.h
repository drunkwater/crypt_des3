// crypt.h : Include file for standard system include files,
// or project specific include files.

#pragma once

// TODO: Reference additional headers your program requires here.


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cdefs.h"
#include "getopt.h"
#include "md5.h"
#include "des.h"


typedef signed char __s8;
typedef unsigned char __u8;

typedef signed short __s16;
typedef unsigned short __u16;

typedef signed int __s32;
typedef unsigned int __u32;

typedef signed long long __s64;
typedef unsigned long long __u64;



#if !defined(SW_VER_MAJOR)
#define SW_VER_MAJOR 1
#endif

#if !defined(SW_VER_MINOR)
#define SW_VER_MINOR 0
#endif

#if !defined(SW_VER_REVISION)
#define SW_VER_REVISION 0
#endif

#if !defined(SW_VER_BUILD_ID)
#define SW_VER_BUILD_ID 0
#endif


#define __STR__(s)     #s
#define MACRO2STR(s)      __STR__(s)          // church
#define __VER_CONS__(a,b,c,d)  a##.##b##.##c##.##d
#define VER_CONS(a,b,c,d)   __VER_CONS__(a,b,c,d)       // church




#ifdef NDEBUG
#define C_DEBUG(fmt, ...)
#else
#define C_DEBUG(fmt, ...) fprintf(stderr, "[%s, %d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#endif

/*--------------------------------------------------------------------------------*/

#define _LITTLE_ENDIAN


#ifdef _LITTLE_ENDIAN
__u32
my_swap32(const __u32 x) {
	return ((x & 0xFF) << 24) | ((x >> 24) & 0xFF)
		| ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8);
}

__u16
my_swap16(const __u16 x) {
	return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF);
}

#    define htonl(x)    my_swap32(x)
#    define ntohl(x)    my_swap32(x)
#    define ntohs(x)    my_swap16(x)
#    define htons(x)    my_swap16(x)


#else

#    define htonl(x)    (x)
#    define ntohl(x)    (x)
#    define ntohs(x)    (x)
#    define htons(x)    (x)

#endif

#ifndef LONG_MAX
# define LONG_MAX (2147483647L)
#endif
#ifndef	SSIZE_MAX
# define SSIZE_MAX	LONG_MAX
#endif

#ifndef __ssize_t_defined
typedef long long ssize_t;
# define __ssize_t_defined
#endif

#ifndef PATH_MAX
#define PATH_MAX (4096)
#endif

#ifndef false
#define false 0
#endif
#ifndef true
#define true (!false)
#endif

#define MAXBUFSIZE (4096)
