#pragma once

#ifndef GLIBC_GETOPT_H
#define GLIBC_GETOPT_H

#include "cdefs.h"

__BEGIN_DECLS


/* The type of the 'argv' argument to getopt_long and getopt_long_only
is properly 'char **', since both functions may write to the array
(in order to move all the options to the beginning).  However, for
compatibility with old versions of LSB, glibc has to use 'char *const *'
instead.  */
#ifndef __getopt_argv_const
# define __getopt_argv_const const
#endif


/* This header should not be used directly; include getopt.h or
unistd.h instead.  Unlike most bits headers, it does not have
a protective #error, because the guard macro for getopt.h in
gnulib is not fixed.  */



/* For communication from 'getopt' to the caller.
When 'getopt' finds an option that takes an argument,
the argument value is returned here.
Also, when 'ordering' is RETURN_IN_ORDER,
each non-option ARGV-element is returned here.  */

extern char *optarg;

/* Index in ARGV of the next element to be scanned.
This is used for communication to and from the caller
and for communication between successive calls to 'getopt'.

On entry to 'getopt', zero means this is the first call; initialize.

When 'getopt' returns -1, this is the index of the first of the
non-option elements that the caller should itself scan.

Otherwise, 'optind' communicates from one call to the next
how much of ARGV has been scanned so far.  */

extern int optind;

/* Callers store zero here to inhibit the error message 'getopt' prints
for unrecognized options.  */

extern int opterr;

/* Set to an option character which was unrecognized.  */

extern int optopt;

/* Get definitions and prototypes for functions to process the
arguments in ARGV (ARGC of them, minus the program name) for
options given in OPTS.

Return the option character from OPTS just read.  Return -1 when
there are no more options.  For unrecognized options, or options
missing arguments, 'optopt' is set to the option letter, and '?' is
returned.

The OPTS string is a list of characters which are recognized option
letters, optionally followed by colons, specifying that that letter
takes an argument, to be placed in 'optarg'.

If a letter in OPTS is followed by two colons, its argument is
optional.  This behavior is specific to the GNU 'getopt'.

The argument '--' causes premature termination of argument
scanning, explicitly telling 'getopt' that there are no more
options.

If OPTS begins with '-', then non-option arguments are treated as
arguments to the option '\1'.  This behavior is specific to the GNU
'getopt'.  If OPTS begins with '+', or POSIXLY_CORRECT is set in
the environment, then do not permute arguments.

For standards compliance, the 'argv' argument has the type
char *const *, but this is inaccurate; if argument permutation is
enabled, the argv array (not the strings it points to) must be
writable.  */

extern int getopt(int ___argc, char *const *___argv, const char *__shortopts)
__THROW __nonnull((2, 3));



/* This header should not be used directly; include getopt.h instead.
Unlike most bits headers, it does not have a protective #error,
because the guard macro for getopt.h in gnulib is not fixed.  */

//__BEGIN_DECLS

/* Describe the long-named options requested by the application.
The LONG_OPTIONS argument to getopt_long or getopt_long_only is a vector
of 'struct option' terminated by an element containing a name which is
zero.

The field 'has_arg' is:
no_argument		(or 0) if the option does not take an argument,
required_argument	(or 1) if the option requires an argument,
optional_argument 	(or 2) if the option takes an optional argument.

If the field 'flag' is not NULL, it points to a variable that is set
to the value given in the field 'val' when the option is found, but
left unchanged if the option is not found.

To have a long-named option do something other than set an 'int' to
a compiled-in constant, such as set a value from 'optarg', set the
option's 'flag' field to zero and its 'val' field to a nonzero
value (the equivalent single-letter option character, if there is
one).  For long options that have a zero 'flag' field, 'getopt'
returns the contents of the 'val' field.  */

struct option
{
	const char *name;
	/* has_arg can't be an enum because some compilers complain about
	type mismatches in all the code that assumes it is an int.  */
	int has_arg;
	int *flag;
	int val;
};

/* Names for the values of the 'has_arg' field of 'struct option'.  */

#define no_argument		0
#define required_argument	1
#define optional_argument	2

extern int getopt_long(int ___argc, char *__getopt_argv_const *___argv,
	const char *__shortopts,
	const struct option *__longopts, int *__longind)
	__THROW __nonnull((2, 3));
extern int getopt_long_only(int ___argc, char *__getopt_argv_const *___argv,
	const char *__shortopts,
	const struct option *__longopts, int *__longind)
	__THROW __nonnull((2, 3));























extern int _getopt_internal(int ___argc, char **___argv,
	const char *__shortopts,
	const struct option *__longopts, int *__longind,
	int __long_only, int __posixly_correct);


/* Reentrant versions which can handle parsing multiple argument
vectors at the same time.  */

/* Describe how to deal with options that follow non-option ARGV-elements.

REQUIRE_ORDER means don't recognize them as options; stop option
processing when the first non-option is seen.  This is what POSIX
specifies should happen.

PERMUTE means permute the contents of ARGV as we scan, so that
eventually all the non-options are at the end.  This allows options
to be given in any order, even with programs that were not written
to expect this.

RETURN_IN_ORDER is an option available to programs that were
written to expect options and other ARGV-elements in any order
and that care about the ordering of the two.  We describe each
non-option ARGV-element as if it were the argument of an option
with character code 1.

The special argument '--' forces an end of option-scanning regardless
of the value of 'ordering'.  In the case of RETURN_IN_ORDER, only
'--' can cause 'getopt' to return -1 with 'optind' != ARGC.  */

enum __ord
{
	REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
};

/* Data type for reentrant functions.  */
struct _getopt_data
{
	/* These have exactly the same meaning as the corresponding global
	variables, except that they are used for the reentrant
	versions of getopt.  */
	int optind;
	int opterr;
	int optopt;
	char *optarg;

	/* Internal members.  */

	/* True if the internal members have been initialized.  */
	int __initialized;

	/* The next char to be scanned in the option-element
	in which the last option character we returned was found.
	This allows us to pick up the scan where we left off.

	If this is zero, or a null string, it means resume the scan
	by advancing to the next ARGV-element.  */
	char *__nextchar;

	/* See __ord above.  */
	enum __ord __ordering;

	/* Handle permutation of arguments.  */

	/* Describe the part of ARGV that contains non-options that have
	been skipped.  'first_nonopt' is the index in ARGV of the first
	of them; 'last_nonopt' is the index after the last of them.  */

	int __first_nonopt;
	int __last_nonopt;
};

/* The initializer is necessary to set OPTIND and OPTERR to their
default values and to clear the initialization flag.  */
#define _GETOPT_DATA_INITIALIZER	{ 1, 1 }

extern int _getopt_internal_r(int ___argc, char **___argv,
	const char *__shortopts,
	const struct option *__longopts, int *__longind,
	int __long_only, struct _getopt_data *__data,
	int __posixly_correct);

extern int _getopt_long_r(int ___argc, char **___argv,
	const char *__shortopts,
	const struct option *__longopts, int *__longind,
	struct _getopt_data *__data);

extern int _getopt_long_only_r(int ___argc, char **___argv,
	const char *__shortopts,
	const struct option *__longopts,
	int *__longind,
	struct _getopt_data *__data);







__END_DECLS

#endif