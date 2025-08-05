ACLOCAL_AMFLAGS = -I m4

# SASL plugin directory (same as cyrus-sasl-xoauth2-idp)
pkglibdir = ${libdir}/sasl2

# Build the OAuth2/OIDC SASL plugin as shared library
pkglib_LTLIBRARIES = liboauth2.la

# Source files
liboauth2_la_SOURCES = \
    oauth2_types.h \
    oauth2_plugin.h \
    oauth2_init.c \
    oauth2_config.c \
    oauth2_server.c \
    oauth2_client.c

# Compiler flags
liboauth2_la_CPPFLAGS = \
    $(CYRUS_SASL_CPPFLAGS) \
    $(OAUTH2_CPPFLAGS) \
    -DSASL_PLUGINDIR=\"$(sasl_plugindir)\"

# Linker flags
liboauth2_la_LDFLAGS = \
    $(CYRUS_SASL_LDFLAGS) \
    $(OAUTH2_LDFLAGS) \
    -module \
    -avoid-version \
    -export-dynamic \
    -no-undefined

# Required libraries
liboauth2_la_LIBADD = \
    -loauth2 \
    -lcjose \
    -ljansson \
    -lcurl \
    -lssl \
    -lcrypto

# Unit tests
check_PROGRAMS = \
    tests/unit/test_config \
    tests/unit/test_jwt \
    tests/unit/test_plugin

# Integration tests - use noinst_PROGRAMS for programs not installed
noinst_PROGRAMS = \
    tests/integration/integration_test

# Test sources and flags
tests_unit_test_config_SOURCES = \
    tests/unit/test_config.c \
    tests/unit/test_framework.c \
    tests/unit/mock_sasl.c
tests_unit_test_config_CPPFLAGS = $(liboauth2_la_CPPFLAGS) -I$(srcdir)
tests_unit_test_config_LDADD = liboauth2.la

tests_unit_test_jwt_SOURCES = \
    tests/unit/test_jwt.c \
    tests/unit/test_framework.c \
    tests/unit/mock_sasl.c
tests_unit_test_jwt_CPPFLAGS = $(liboauth2_la_CPPFLAGS) -I$(srcdir)
tests_unit_test_jwt_LDADD = liboauth2.la -ljansson

tests_unit_test_plugin_SOURCES = \
    tests/unit/test_plugin.c \
    tests/unit/test_framework.c \
    tests/unit/mock_sasl.c
tests_unit_test_plugin_CPPFLAGS = $(liboauth2_la_CPPFLAGS) -I$(srcdir)
tests_unit_test_plugin_LDADD = liboauth2.la

# Integration test configuration (automake requires underscores instead of slashes)
tests_integration_integration_test_SOURCES = \
    tests/integration/integration_test.c \
    tests/integration/mini_client.c \
    tests/integration/mini_server.c \
    tests/integration/test_utils.c
tests_integration_integration_test_CPPFLAGS = $(liboauth2_la_CPPFLAGS) -I$(srcdir) -I$(srcdir)/tests/integration
tests_integration_integration_test_LDADD = liboauth2.la -lsasl2

# Run tests after build
check-local:
	@echo "Running OAuth2 SASL Plugin Unit Tests..."
	@echo "======================================="
	@for test in $(check_PROGRAMS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo "All unit tests passed!"

# Integration test targets
.PHONY: integration check-integration test-integration
integration: $(noinst_PROGRAMS)

check-integration: integration
	@echo "Running OAuth2 SASL Plugin Integration Tests..."
	@echo "==============================================="
	@for test in $(noinst_PROGRAMS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo "All integration tests passed!"

test-integration: check-integration

# Additional files to distribute
EXTRA_DIST = \
    README.md \
    COPYING \
    AUTHORS \
    ChangeLog \
    NEWS \
    autogen.sh \
    tests/unit/test_framework.h \
    tests/unit/test_framework.c \
    tests/unit/test_config.c \
    tests/unit/test_jwt.c \
    tests/unit/test_plugin.c \
    tests/unit/Makefile.tests \
    tests/e2e/test_e2e.py \
    tests/e2e/mock_oauth2_server.py \
    tests/e2e/docker-compose.test.yml \
    tests/e2e/test.dockerfile \
    tests/e2e/requirements.txt \
    tests/run_tests.sh \
    tests/README.md \
    tests/integration/README.md \
    tests/integration/test_utils.h \
    tests/integration/test_utils.c \
    tests/integration/mini_client.c \
    tests/integration/mini_server.c \
    tests/integration/integration_test.c

# Documentation files
doc_DATA = README.md

# Create symbolic links for plugin names
install-data-hook:
	cd $(DESTDIR)$(pkglibdir) && \
	if test -f liboauth2.so; then \
		$(LN_S) -f liboauth2.so libxoauth2.so; \
		$(LN_S) -f liboauth2.so liboauthbearer.so; \
	fi

uninstall-hook:
	cd $(DESTDIR)$(pkglibdir) && \
	rm -f libxoauth2.so liboauthbearer.so

# Clean up generated files
CLEANFILES = *.la *.lo *.o .libs/*

# Build script for autogen
AUTOGEN_SCRIPT = autogen.sh

$(AUTOGEN_SCRIPT):
	@echo '#!/bin/bash' > $@
	@echo 'set -e' >> $@
	@echo 'echo "Generating build system..."' >> $@
	@echo 'autoreconf -fiv' >> $@
	@echo 'echo "Build system generated successfully."' >> $@
	@echo 'echo "Run ./configure to configure the build."' >> $@
	@chmod +x $@

# Maintainer targets
maintainer-clean-local:
	-rm -rf .deps .libs
	-rm -f aclocal.m4 config.guess config.h.in config.sub configure
	-rm -f depcomp install-sh ltmain.sh missing
	-rm -f Makefile.in

# Development targets
.PHONY: debug install-debug uninstall-debug

debug: CFLAGS := $(CFLAGS) -g -O0 -DDEBUG -Wall -Wextra -Wpedantic
debug: all

install-debug: debug install

uninstall-debug: uninstall

# Testing targets (placeholder for future implementation)
.PHONY: check-syntax test

check-syntax:
	@echo "Checking syntax..."
	@for file in $(liboauth2_la_SOURCES); do \
		if echo "$$file" | grep -q '\.c$$'; then \
			echo "Checking $$file..."; \
			$(CC) $(liboauth2_la_CPPFLAGS) -fsyntax-only $$file; \
		fi; \
	done
	@echo "Syntax check completed."

test: check check-integration
	@echo "All tests completed successfully!"

# Help target
.PHONY: help

help:
	@echo "Available targets:"
	@echo "  all                 - Build the plugin"
	@echo "  install             - Install the plugin"
	@echo "  uninstall           - Uninstall the plugin" 
	@echo "  clean               - Clean build files"
	@echo "  debug               - Build with debug symbols"
	@echo "  install-debug       - Build and install debug version"
	@echo "  check               - Run unit tests"
	@echo "  integration         - Build integration tests"
	@echo "  test-integration    - Run integration tests"
	@echo "  test                - Run all tests (unit + integration)"
	@echo "  check-syntax        - Check source code syntax"
	@echo "  help                - Show this help message"