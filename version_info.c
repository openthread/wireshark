/* version_info.c
 * Routines to report version information for Wireshark programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#ifdef _WIN32
#include <windows.h>
#elif __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#elif __linux__
#include <sys/sysinfo.h>
#endif

#include <glib.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "version.h"

#include "version_info.h"

#include <wsutil/cpu_info.h>
#include <wsutil/copyright_info.h>
#include <wsutil/os_version_info.h>
#include <wsutil/ws_printf.h> /* ws_debug_printf */
#include <wsutil/plugins.h>

/*
 * If the string doesn't end with a newline, append one.
 * Then word-wrap it to 80 columns.
 */
static void
end_string(GString *str)
{
	size_t point;
	char *p, *q;

	point = str->len;
	if (point == 0 || str->str[point - 1] != '\n')
		g_string_append(str, "\n");
	p = str->str;
	while (*p != '\0') {
		q = strchr(p, '\n');
		if (q - p > 80) {
			/*
			 * Break at or before this point.
			 */
			q = p + 80;
			while (q > p && *q != ' ')
				q--;
			if (q != p)
				*q = '\n';
		}
		p = q + 1;
	}
}

static const gchar *
get_zlib_compiled_version_info(void)
{
#ifdef HAVE_ZLIB
#ifdef ZLIB_VERSION
	return "with zlib "ZLIB_VERSION;
#else
	return "with zlib (version unknown)";
#endif /* ZLIB_VERSION */
#else
	return "without zlib";
#endif /* HAVE_ZLIB */
}

/*
 * Get various library compile-time versions, put them in a GString,
 * and return the GString.
 *
 * "prepend_info" is called at the start to prepend any additional
 * information before the standard library information.
 *
 * "append_info" is called at the end to append any additional
 * information after the standard library information.  This is
 * required in order to, for example, put Qt information at the
 * end of the string, as we don't use Qt in TShark.
 */
GString *
get_compiled_version_info(void (*prepend_info)(GString *),
			  void (*append_info)(GString *))
{
	GString *str;

	str = g_string_new("Compiled ");

	if (sizeof(str) == 4)
		g_string_append(str, "(32-bit) ");
	else
		g_string_append(str, "(64-bit) ");

	if (prepend_info) {
		(*prepend_info)(str);
		g_string_append(str, ", ");
	}

	/* GLIB */
	g_string_append(str, "with ");
	g_string_append_printf(str,
#ifdef GLIB_MAJOR_VERSION
	    "GLib %d.%d.%d", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
	    GLIB_MICRO_VERSION);
#else
	    "GLib (version unknown)");
#endif

	g_string_append_printf(str, ", %s", get_zlib_compiled_version_info());

	/* Additional application-dependent information */
	if (append_info)
		(*append_info)(str);
	g_string_append(str, ".");

	end_string(str);

	return str;
}

static void
get_mem_info(GString *str)
{
	gint64 memsize = 0;

#ifdef _WIN32
	MEMORYSTATUSEX statex;

	statex.dwLength = sizeof (statex);

	if (GlobalMemoryStatusEx(&statex))
		memsize = statex.ullTotalPhys;
#elif __APPLE__
	size_t len = sizeof(memsize);
	sysctlbyname("hw.memsize", &memsize, &len, NULL, 0);
#elif __linux__
	struct sysinfo info;
        if (sysinfo(&info) == 0)
		memsize = info.totalram * info.mem_unit;
#endif

	if (memsize > 0)
		g_string_append_printf(str, ", with ""%" G_GINT64_MODIFIER "d" " MB of physical memory", memsize/(1024*1024));
}

/*
 * Get compiler information, and append it to the GString.
 */
static void
get_compiler_info(GString *str)
{
	/*
	 * See https://sourceforge.net/apps/mediawiki/predef/index.php?title=Compilers
	 * information on various defined strings.
	 *
	 * GCC's __VERSION__ is a nice text string for humans to
	 * read.  The page at sourceforge.net largely describes
	 * numeric #defines that encode the version; if the compiler
	 * doesn't also offer a nice printable string, we try prettifying
	 * the number somehow.
	 */
#if defined(__GNUC__) && defined(__VERSION__)
	/*
	 * Clang and llvm-gcc also define __GNUC__ and __VERSION__;
	 * distinguish between them.
	 */
#if defined(__clang__)
	/*
	 * Microsoft have a version of their compiler that has Clang
	 * as the front end and their code generator as the back end.
	 *
	 * My head asplode.
	 */
  #if defined(__MSC_VER)
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d.%d clang/C2 %s and -fno-ms-compatibility.\n",
	    (_MSC_VER / 100) - 6, _MSC_VER % 100, __VERSION__);
  #else
	g_string_append_printf(str, "\n\nBuilt using clang %s.\n", __VERSION__);
  #endif /* defined(__MSC_VER) */
#elif defined(__llvm__)
	g_string_append_printf(str, "\n\nBuilt using llvm-gcc %s.\n", __VERSION__);
#else /* boring old GCC */
	g_string_append_printf(str, "\n\nBuilt using gcc %s.\n", __VERSION__);
#endif /* llvm */
#elif defined(__HP_aCC)
	g_string_append_printf(str, "\n\nBuilt using HP aCC %d.\n", __HP_aCC);
#elif defined(__xlC__)
	g_string_append_printf(str, "\n\nBuilt using IBM XL C %d.%d\n",
	    (__xlC__ >> 8) & 0xFF, __xlC__ & 0xFF);
#ifdef __IBMC__
	if ((__IBMC__ % 10) != 0)
		g_string_append_printf(str, " patch %d", __IBMC__ % 10);
#endif /* __IBMC__ */
	g_string_append_printf(str, "\n");
#elif defined(__INTEL_COMPILER)
	g_string_append_printf(str, "\n\nBuilt using Intel C %d.%d",
	    __INTEL_COMPILER / 100, (__INTEL_COMPILER / 10) % 10);
	if ((__INTEL_COMPILER % 10) != 0)
		g_string_append_printf(str, " patch %d", __INTEL_COMPILER % 10);
#ifdef __INTEL_COMPILER_BUILD_DATE
	g_string_sprinta(str, ", compiler built %04d-%02d-%02d",
	    __INTEL_COMPILER_BUILD_DATE / 10000,
	    (__INTEL_COMPILER_BUILD_DATE / 100) % 100,
	    __INTEL_COMPILER_BUILD_DATE % 100);
#endif /* __INTEL_COMPILER_BUILD_DATE */
	g_string_append_printf(str, "\n");
#elif defined(_MSC_FULL_VER)
# if _MSC_FULL_VER > 99999999
	/* Quote from the web:
	 * Bakersfield: DevDiv's upper management determines the scheduling of new major versions.
	 * They also decided to increment the product version from 12 (for VS 2013) to 14 (for VS 2015).
	 * However, the C++ compiler's version incremented normally, from 18 to 19.
	 * (It's larger because the C++ compiler predates the "Visual" in Visual C++.)
	 * XXX? Should we just output the compiler version?
	 */
    int compiler_major_version = (_MSC_FULL_VER / 10000000), visual_studio_ver;

    if (compiler_major_version < 19) {
        visual_studio_ver = compiler_major_version - 6;
    }else{
        visual_studio_ver = compiler_major_version - 5;
    }

    g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d",
                   visual_studio_ver,
			       (_MSC_FULL_VER / 100000) % 100);
#  if (_MSC_FULL_VER % 100000) != 0
	g_string_append_printf(str, " build %d",
			       _MSC_FULL_VER % 100000);
#  endif
# else
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d",
			       (_MSC_FULL_VER / 1000000) - 6,
			       (_MSC_FULL_VER / 10000) % 100);
#  if (_MSC_FULL_VER % 10000) != 0
	g_string_append_printf(str, " build %d",
			       _MSC_FULL_VER % 10000);
#  endif
# endif
	g_string_append_printf(str, "\n");
#elif defined(_MSC_VER)
	/* _MSC_FULL_VER not defined, but _MSC_VER defined */
  #if defined(__clang__)
	/* More head asplosion; see above. */
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d.%d clang/C2 %s.\n",
	    (_MSC_VER / 100) - 6, _MSC_VER % 100, __VERSION__);
  #else
	g_string_append_printf(str, "\n\nBuilt using clang %s.\n", __VERSION__);
  #endif /* defined(__MSC_VER) */
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d\n",
	    (_MSC_VER / 100) - 6, _MSC_VER % 100);
#elif defined(__SUNPRO_C)
	g_string_append_printf(str, "\n\nBuilt using Sun C %d.%d",
	    (__SUNPRO_C >> 8) & 0xF, (__SUNPRO_C >> 4) & 0xF);
	if ((__SUNPRO_C & 0xF) != 0)
		g_string_append_printf(str, " patch %d", __SUNPRO_C & 0xF);
	g_string_append_printf(str, "\n");
#endif
}

/* XXX - is the setlocale() return string opaque? For glibc the separator is ';' */
static gchar *
get_locale(void)
{
	const gchar *lang;
	gchar **locv, *loc;

	lang = setlocale(LC_ALL, NULL);
	if (lang == NULL) {
		return NULL;
	}

	locv = g_strsplit(lang, ";", -1);
	loc = g_strjoinv(", ", locv);
	g_strfreev(locv);
	return loc;
}

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 *
 * "additional_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * libcap information at the end of the string, as we currently
 * don't use libcap in TShark.
 */
GString *
get_runtime_version_info(void (*additional_info)(GString *))
{
	GString *str;
	gchar *lang;

	str = g_string_new("Running on ");

	get_os_version_info(str);

	/* CPU Info */
	get_cpu_info(str);

	/* Get info about installed memory */
	get_mem_info(str);

	/*
	 * Locale.
	 *
	 * This returns the C language's locale information; this
	 * returns the locale that's actually in effect, even if
	 * it doesn't happen to match the settings of any of the
	 * locale environment variables.
	 *
	 * On Windows get_locale returns the full language, country
	 * name, and code page, e.g. "English_United States.1252":
	 * https://msdn.microsoft.com/en-us/library/x99tb11d.aspx
	 */
	if ((lang = get_locale()) != NULL) {
		g_string_append_printf(str, ", with locale %s", lang);
		g_free(lang);
	}
	else {
		g_string_append(str, ", with default locale");
	}


	/* Additional application-dependent information */
	if (additional_info)
		(*additional_info)(str);

	/* zlib */
#if defined(HAVE_ZLIB) && !defined(_WIN32)
	g_string_append_printf(str, ", with zlib %s", zlibVersion());
#endif

	/* plugins */
#ifdef HAVE_PLUGINS
	if (g_module_supported()) {
		g_string_append_printf(str, ", binary plugins supported (%d loaded)", plugins_get_count());
	}
	else {
		g_string_append(str, ", binary plugins not supported");
	}
#endif

	g_string_append(str, ".");

	/* Compiler info */
	get_compiler_info(str);

	end_string(str);

	return str;
}

void
show_version(const gchar *prog_name_str, GString *comp_info_str,
	     GString *runtime_info_str)
{
	ws_debug_printf("%s %s %s\n"
	       "\n"
	       "%s"
	       "\n"
	       "%s"
	       "\n"
	       "%s",
	       prog_name_str, "Thread1.2-0.55",get_ws_vcs_version_info(), get_copyright_info(),
	       comp_info_str->str, runtime_info_str->str);
}

/*
 * Return a version number string for Wireshark, including, for builds
 * from a tree checked out from Wireshark's version control system,
 * something identifying what version was checked out.
 */
const char *
get_ws_vcs_version_info(void)
{
#ifdef VCSVERSION
	return VERSION " (" VCSVERSION ")";
#else
	return VERSION;
#endif
}

void
get_ws_version_number(int *major, int *minor, int *micro)
{
	if (major)
		*major = VERSION_MAJOR;
	if (minor)
		*minor = VERSION_MINOR;
	if (micro)
		*micro = VERSION_MICRO;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
