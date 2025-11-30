#!/bin/bash
#
# VEX Kernel Checker Release Script
#
# This script automates the release process:
# 1. Validates the release (tests, linting, version consistency)
# 2. Updates version numbers across all files
# 3. Updates CHANGELOG with release date
# 4. Builds the package
# 5. Optionally creates git tag and pushes
# 6. Optionally uploads to PyPI
#
# Usage:
#   ./scripts/release.sh [version] [options]
#
# Examples:
#   ./scripts/release.sh 2.2.0              # Prepare release 2.2.0
#   ./scripts/release.sh 2.2.0 --dry-run    # Dry run (no changes)
#   ./scripts/release.sh 2.2.0 --push       # Also push to git and PyPI
#   ./scripts/release.sh --check            # Just run validation checks
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Files that contain version numbers
VERSION_FILES=(
    "pyproject.toml"
    "vex_kernel_checker/__init__.py"
)

# Default options
DRY_RUN=false
PUSH=false
CHECK_ONLY=false
SKIP_TESTS=false

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

print_info() { print_msg "$BLUE" "ℹ️  $1"; }
print_success() { print_msg "$GREEN" "✅ $1"; }
print_warning() { print_msg "$YELLOW" "⚠️  $1"; }
print_error() { print_msg "$RED" "❌ $1"; }

# Show usage
usage() {
    echo "Usage: $0 [version] [options]"
    echo ""
    echo "Arguments:"
    echo "  version          New version number (e.g., 2.2.0)"
    echo ""
    echo "Options:"
    echo "  --dry-run        Show what would be done without making changes"
    echo "  --push           Push to git and upload to PyPI after release"
    echo "  --check          Only run validation checks (no version argument needed)"
    echo "  --skip-tests     Skip running tests (use with caution)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 2.2.0              # Prepare release 2.2.0"
    echo "  $0 2.2.0 --dry-run    # Dry run (no changes)"
    echo "  $0 2.2.0 --push       # Also push to git and PyPI"
    echo "  $0 --check            # Just run validation checks"
    exit 1
}

# Get current version from pyproject.toml
get_current_version() {
    grep -E '^version = ' "$PROJECT_DIR/pyproject.toml" | sed 's/version = "\(.*\)"/\1/'
}

# Validate version format (semver)
validate_version() {
    local version=$1
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        print_error "Invalid version format: $version"
        print_info "Version must follow semver format: X.Y.Z or X.Y.Z-suffix"
        exit 1
    fi
}

# Check if working directory is clean
check_git_clean() {
    if [[ -n $(git -C "$PROJECT_DIR" status --porcelain) ]]; then
        print_warning "Working directory has uncommitted changes"
        git -C "$PROJECT_DIR" status --short
        echo ""
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Working directory is clean"
    fi
}

# Run tests
run_tests() {
    print_info "Running tests..."
    cd "$PROJECT_DIR"

    if ! make test-quick; then
        print_error "Quick tests failed"
        exit 1
    fi
    print_success "Quick tests passed"

    if ! make lint; then
        print_error "Linting failed"
        exit 1
    fi
    print_success "Linting passed"

    if ! make format-check; then
        print_error "Format check failed"
        print_info "Run 'make format' to fix formatting issues"
        exit 1
    fi
    print_success "Format check passed"
}

# Check version consistency across files
check_version_consistency() {
    local expected_version=$1
    print_info "Checking version consistency..."

    local inconsistent=false

    for file in "${VERSION_FILES[@]}"; do
        local filepath="$PROJECT_DIR/$file"
        if [[ ! -f "$filepath" ]]; then
            print_warning "File not found: $file"
            continue
        fi

        local version
        if [[ "$file" == "pyproject.toml" ]]; then
            version=$(grep -E '^version = ' "$filepath" | sed 's/version = "\(.*\)"/\1/')
        elif [[ "$file" == *"__init__.py" ]]; then
            version=$(grep -E '^__version__ = ' "$filepath" | sed 's/__version__ = "\(.*\)"/\1/')
        fi

        if [[ "$version" != "$expected_version" ]]; then
            print_warning "$file: $version (expected $expected_version)"
            inconsistent=true
        else
            print_success "$file: $version"
        fi
    done

    if $inconsistent; then
        return 1
    fi
    return 0
}

# Update version in all files
update_version() {
    local new_version=$1
    local old_version
    old_version=$(get_current_version)

    print_info "Updating version from $old_version to $new_version..."

    if $DRY_RUN; then
        print_info "[DRY RUN] Would update version in:"
        for file in "${VERSION_FILES[@]}"; do
            echo "  - $file"
        done
        return
    fi

    # Update pyproject.toml
    sed -i "s/^version = \".*\"/version = \"$new_version\"/" "$PROJECT_DIR/pyproject.toml"

    # Update __init__.py
    sed -i "s/^__version__ = \".*\"/__version__ = \"$new_version\"/" "$PROJECT_DIR/vex_kernel_checker/__init__.py"

    print_success "Version updated to $new_version"
}

# Update CHANGELOG with release date
update_changelog() {
    local version=$1
    local date
    date=$(date +%Y-%m-%d)

    print_info "Updating CHANGELOG..."

    if $DRY_RUN; then
        print_info "[DRY RUN] Would update CHANGELOG.md:"
        print_info "  - Change [Unreleased] to [$version] - $date"
        return
    fi

    # Check if [Unreleased] section exists
    if grep -q "## \[Unreleased\]" "$PROJECT_DIR/CHANGELOG.md"; then
        # Replace [Unreleased] with version and date
        sed -i "s/## \[Unreleased\]/## [$version] - $date/" "$PROJECT_DIR/CHANGELOG.md"

        # Add new [Unreleased] section at the top
        sed -i "/^## \[$version\]/i ## [Unreleased]\n\n### Added\n\n### Fixed\n\n### Changed\n\n" "$PROJECT_DIR/CHANGELOG.md"

        print_success "CHANGELOG updated with release date"
    else
        print_warning "No [Unreleased] section found in CHANGELOG.md"
    fi
}

# Build the package
build_package() {
    print_info "Building package..."

    if $DRY_RUN; then
        print_info "[DRY RUN] Would build package"
        return
    fi

    cd "$PROJECT_DIR"

    # Clean previous builds
    rm -rf dist/ build/ *.egg-info/

    # Build
    python3 -m build

    # Verify the build
    if ! twine check dist/*; then
        print_error "Package validation failed"
        exit 1
    fi

    print_success "Package built successfully"
    ls -la dist/
}

# Create git tag
create_git_tag() {
    local version=$1
    local tag="v$version"

    print_info "Creating git tag $tag..."

    if $DRY_RUN; then
        print_info "[DRY RUN] Would create and push tag $tag"
        return
    fi

    # Commit version changes
    cd "$PROJECT_DIR"
    git add -A
    git commit -m "Release $version

- Update version to $version
- Update CHANGELOG with release date

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

    # Create tag
    git tag -a "$tag" -m "Release $version"

    print_success "Git tag $tag created"

    if $PUSH; then
        print_info "Pushing to remote..."
        git push origin main
        git push origin "$tag"
        print_success "Pushed to remote"
    else
        print_info "To push: git push origin main && git push origin $tag"
    fi
}

# Upload to PyPI
upload_to_pypi() {
    print_info "Uploading to PyPI..."

    if $DRY_RUN; then
        print_info "[DRY RUN] Would upload to PyPI"
        return
    fi

    if $PUSH; then
        cd "$PROJECT_DIR"
        twine upload dist/*
        print_success "Uploaded to PyPI"
    else
        print_info "To upload: twine upload dist/*"
    fi
}

# Main release process
main() {
    local version=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --push)
                PUSH=true
                shift
                ;;
            --check)
                CHECK_ONLY=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                ;;
            *)
                version=$1
                shift
                ;;
        esac
    done

    cd "$PROJECT_DIR"

    echo ""
    echo "========================================"
    echo "  VEX Kernel Checker Release Script"
    echo "========================================"
    echo ""

    # Check-only mode
    if $CHECK_ONLY; then
        print_info "Running validation checks only..."
        echo ""

        local current_version
        current_version=$(get_current_version)
        print_info "Current version: $current_version"

        check_git_clean

        if ! $SKIP_TESTS; then
            run_tests
        fi

        if check_version_consistency "$current_version"; then
            print_success "Version is consistent across all files"
        else
            print_error "Version inconsistency detected"
            exit 1
        fi

        echo ""
        print_success "All checks passed!"
        exit 0
    fi

    # Version is required for release
    if [[ -z "$version" ]]; then
        print_error "Version is required"
        usage
    fi

    validate_version "$version"

    local current_version
    current_version=$(get_current_version)
    print_info "Current version: $current_version"
    print_info "New version: $version"

    if $DRY_RUN; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi

    echo ""

    # Step 1: Check git status
    check_git_clean

    # Step 2: Run tests
    if ! $SKIP_TESTS; then
        run_tests
    else
        print_warning "Skipping tests (--skip-tests)"
    fi

    # Step 3: Update version
    update_version "$version"

    # Step 4: Update CHANGELOG
    update_changelog "$version"

    # Step 5: Build package
    build_package

    # Step 6: Create git tag
    create_git_tag "$version"

    # Step 7: Upload to PyPI (if --push)
    if $PUSH; then
        upload_to_pypi
    fi

    echo ""
    echo "========================================"
    print_success "Release $version complete!"
    echo "========================================"
    echo ""

    if ! $PUSH; then
        print_info "Next steps:"
        echo "  1. Review the changes: git diff HEAD~1"
        echo "  2. Push to remote: git push origin main && git push origin v$version"
        echo "  3. Upload to PyPI: twine upload dist/*"
    fi
}

main "$@"
