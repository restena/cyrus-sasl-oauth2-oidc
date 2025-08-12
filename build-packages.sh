#!/bin/bash

# Unified build script for both DEB and RPM packages using Docker
# Usage: ./build-packages.sh [os] [version] [target] [arch]
# Examples:
#   ./build-packages.sh debian trixie packages amd64
#   ./build-packages.sh fedora 41 packages x86_64
#   ./build-packages.sh rhel 9 packages x86_64

set -e

OS=${1:-debian}
VERSION=${2:-trixie}
TARGET=${3:-packages}
ARCH=${4:-amd64}
IMAGE_NAME="cyrus-sasl-oauth2-oidc"

# Validate OS type
case $OS in
    debian)
        DOCKERFILE="Dockerfile.build"
        BUILD_ARG="DEBIAN_VERSION"
        ;;
    fedora)
        DOCKERFILE="Dockerfile.fedora"
        BUILD_ARG="FEDORA_VERSION"
        ;;
    *)
        echo "❌ Error: Unsupported OS '$OS'. Supported: debian, fedora"
        exit 1
        ;;
esac

# Map architecture names
DOCKER_ARCH="$ARCH"
if [ "$OS" != "debian" ]; then
    # For RPM builds, map x86_64 -> amd64, aarch64 -> arm64
    case $ARCH in
        x86_64) DOCKER_ARCH="amd64" ;;
        aarch64) DOCKER_ARCH="arm64" ;;
    esac
fi

echo "🚀 Building $OS package for $VERSION ($ARCH)..."
echo "📋 Configuration:"
echo "   OS: $OS"
echo "   Version: $VERSION"
echo "   Architecture: $ARCH (Docker: $DOCKER_ARCH)"
echo "   Target: $TARGET"
echo "   Dockerfile: $DOCKERFILE"

# Create packages directory
mkdir -p packages

# Build the Docker image
echo "📦 Building Docker image..."
if [ "$DOCKER_ARCH" != "amd64" ]; then
    # Use buildx for multi-arch builds
    docker buildx build \
        --platform "linux/$DOCKER_ARCH" \
        --target "$TARGET" \
        --tag "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
        --file "$DOCKERFILE" \
        --build-arg "$BUILD_ARG=$VERSION" \
        --load \
        .
else
    # Use regular build for AMD64
    docker build \
        --target "$TARGET" \
        --tag "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
        --file "$DOCKERFILE" \
        --build-arg "$BUILD_ARG=$VERSION" \
        .
fi

if [ "$TARGET" = "packages" ]; then
    # Extract packages from the container
    echo "📤 Extracting packages..."
    docker run --rm -v "$(pwd)/packages:/output" \
        "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
        sh -c "cp -r /packages/* /output/"

    echo "✅ Packages extracted to ./packages/"
    echo "📋 Built packages:"
    find packages -name "*.*" -type f -exec ls -lh {} \;

    # Run linting validation
    echo "🔍 Running package validation..."
    case $OS in
        debian)
            echo "Running lintian validation..."
            docker run --rm -v "$(pwd)/packages:/packages" \
                "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                sh -c "find /packages -name '*.deb' -exec lintian {} \;" || true
            ;;
        fedora|rhel)
            echo "Running rpmlint validation..."
            docker run --rm -v "$(pwd)/packages:/packages" \
                "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                sh -c "find /packages -name '*.rpm' -exec rpmlint {} \;" || true
            ;;
    esac

elif [ "$TARGET" = "test" ]; then
    # Run installation test
    echo "🧪 Testing package installation..."
    case $OS in
        debian)
            docker run --rm "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                bash -c "ls -la /usr/lib/*/sasl2/liboauth2.so"
            ;;
        fedora|rhel)
            docker run --rm "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                bash -c "find /usr/lib* -name 'liboauth2.so*' -type f"
            ;;
    esac
    echo "✅ Package installation test passed!"
fi

echo "🎉 Build completed successfully!"
