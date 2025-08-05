#!/bin/bash
#
# autogen.sh - Generate build system for cyrus-sasl-oauth2-oidc
# Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
#

set -e

echo "Generating build system for cyrus-sasl-oauth2-oidc..."

# Check for required tools
echo "Checking for required autotools..."

REQUIRED_TOOLS="autoreconf aclocal autoconf autoheader automake libtoolize"

for tool in $REQUIRED_TOOLS; do
    if ! command -v $tool >/dev/null 2>&1; then
        echo "Error: $tool is required but not found."
        echo "Please install autotools package (autoconf, automake, libtool)."
        exit 1
    fi
done

echo "All required tools found."

# Create m4 directory if it doesn't exist
if [ ! -d "m4" ]; then
    echo "Creating m4 directory..."
    mkdir -p m4
fi

# Generate the build system
echo "Running autoreconf..."
autoreconf -fiv

echo
echo "Build system generated successfully!"
echo
echo "Next steps:"
echo "  1. Run ./configure [options] to configure the build"
echo "  2. Run make to build the plugin"  
echo "  3. Run make install to install the plugin"
echo
echo "Configuration options:"
echo "  --with-sasl-plugindir=DIR    SASL plugin directory"
echo "  --with-cyrus-sasl-prefix=DIR Cyrus SASL installation prefix"
echo "  --with-oauth2-prefix=DIR     liboauth2 installation prefix"
echo "  --enable-debug               Enable debug build"
echo
echo "Example:"
echo "  ./configure --enable-debug"
echo "  make"
echo "  sudo make install"
echo