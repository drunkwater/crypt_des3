#pragma once

#ifndef _CRYPT_MD5_H
#define _CRYPT_MD5_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


char *crypt(const char *key, const char *salt);

#ifdef __cplusplus
}
#endif


#endif