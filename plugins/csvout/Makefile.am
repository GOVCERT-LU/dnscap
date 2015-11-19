MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = csvout.la
csvout_la_SOURCES = csvout.c
csvout_la_LDFLAGS = -module -avoid-version
