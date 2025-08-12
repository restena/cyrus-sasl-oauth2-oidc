#!/bin/bash

# Build script for Debian packages using Docker
# Usage: ./build-package.sh [debian_version] [target] [arch]

set -e

DEBIAN_VERSION=${1:-trixie}
TARGET=${2:-packages}
ARCH=${3:-amd64}
IMAGE_NAME="cyrus-sasl-oauth2-oidc"

echo "🚀 Building Debian package for $DEBIAN_VERSION ($ARCH)..."

# Build the Docker image
echo "📦 Building Docker image..."
if [ "$ARCH" != "amd64" ]; then
    # Use buildx for multi-arch builds
    docker buildx build \
        --platform "linux/$ARCH" \
        --target "$TARGET" \
        --tag "$IMAGE_NAME:$DEBIAN_VERSION-$ARCH" \
        --file Dockerfile.build \
        --load \
        .
else
    # Use regular build for AMD64
    docker build \
        --target "$TARGET" \
        --tag "$IMAGE_NAME:$DEBIAN_VERSION-$ARCH" \
        --file Dockerfile.build \
        .
fi

# Extract packages if building packages target
if [ "$TARGET" = "packages" ]; then
    echo "📤 Extracting packages..."
    
    # Create output directory
    mkdir -p "dist/$DEBIAN_VERSION-$ARCH"
    
    # Extract packages from Docker image
    docker create --name temp-extract-$ARCH "$IMAGE_NAME:$DEBIAN_VERSION-$ARCH"
    docker cp temp-extract-$ARCH:/packages/ "dist/$DEBIAN_VERSION-$ARCH/"
    docker rm temp-extract-$ARCH
    
    echo "✅ Packages built successfully!"
    echo "📁 Output directory: dist/$DEBIAN_VERSION-$ARCH/packages/"
    ls -la "dist/$DEBIAN_VERSION-$ARCH/packages/"
    
    # Validate packages
    echo "🔍 Validating packages with lintian..."
    docker run --rm \
        -v "$(pwd)/dist/$DEBIAN_VERSION-$ARCH/packages:/packages" \
        "debian:$DEBIAN_VERSION-slim" \
        bash -c "
            apt-get update -qq && apt-get install -y lintian >/dev/null 2>&1
            cd /packages
            for deb in *.deb; do
                echo '=== Validating \$deb ==='
                lintian --no-tag-display-limit \$deb || true
                echo
            done
        "
fi

# Test installation if building test target
if [ "$TARGET" = "test" ]; then
    echo "🧪 Testing package installation..."
    docker run --rm "$IMAGE_NAME:$DEBIAN_VERSION-$ARCH" \
        bash -c "ls -la /usr/lib/*/sasl2/liboauth2.so && echo 'Plugin installed successfully!'"
fi

echo "🎉 Build completed successfully!"
