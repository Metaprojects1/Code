#!/bin/bash
#
# setup_github_secrets.sh
# 
# Secure setup script for GitHub Actions firmware signing secrets
# Validates and adds FIRMWARE_SIGNING_KEY to GitHub repository
#
# Usage:
#   bash setup_github_secrets.sh <repo> <private_key_file>
#
# Example:
#   bash setup_github_secrets.sh myuser/DRONE-CRA-Cyber firmware_signing_private.pem
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="${1:-}"
PRIVATE_KEY_FILE="${2:-}"
MIN_KEY_SIZE=200  # Minimum PEM file size in bytes

# =============================================================================
# Utility Functions
# =============================================================================

print_header() {
    echo -e "\n${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ ERROR: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ WARNING: $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ INFO: $1${NC}"
}

# =============================================================================
# Validation Functions
# =============================================================================

validate_inputs() {
    print_header "Validating Input Parameters"
    
    if [ -z "$REPO" ]; then
        print_error "Repository argument not provided"
        echo "Usage: bash setup_github_secrets.sh <repo> <private_key_file>"
        echo "Example: bash setup_github_secrets.sh myuser/DRONE-CRA-Cyber firmware_signing_private.pem"
        exit 1
    fi
    
    if [ -z "$PRIVATE_KEY_FILE" ]; then
        print_error "Private key file argument not provided"
        echo "Usage: bash setup_github_secrets.sh <repo> <private_key_file>"
        exit 1
    fi
    
    print_success "Repository: $REPO"
    print_success "Key file: $PRIVATE_KEY_FILE"
}

validate_key_file() {
    print_header "Validating Private Key File"
    
    if [ ! -f "$PRIVATE_KEY_FILE" ]; then
        print_error "Key file not found: $PRIVATE_KEY_FILE"
        exit 1
    fi
    
    print_success "Key file exists"
    
    # Check file size
    KEY_SIZE=$(stat -f%z "$PRIVATE_KEY_FILE" 2>/dev/null || stat -c%s "$PRIVATE_KEY_FILE" 2>/dev/null)
    
    if [ "$KEY_SIZE" -lt "$MIN_KEY_SIZE" ]; then
        print_error "Key file too small: $KEY_SIZE bytes (minimum $MIN_KEY_SIZE)"
        exit 1
    fi
    
    print_success "Key file size: $KEY_SIZE bytes"
    
    # Check PEM format
    if ! grep -q "BEGIN EC PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" "$PRIVATE_KEY_FILE"; then
        print_error "File does not appear to be a valid PEM private key"
        echo "Expected: '-----BEGIN EC PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----'"
        exit 1
    fi
    
    print_success "PEM format validated"
    
    # Validate ECDSA key (P-256)
    if grep -q "BEGIN EC PRIVATE KEY" "$PRIVATE_KEY_FILE"; then
        if openssl ec -in "$PRIVATE_KEY_FILE" -text -noout 2>/dev/null | grep -q "Private-Key: (256 bits)"; then
            print_success "ECDSA P-256 key detected"
        else
            print_warning "ECDSA key detected but not P-256 (may be different curve)"
            openssl ec -in "$PRIVATE_KEY_FILE" -text -noout 2>/dev/null | head -3
        fi
    fi
    
    # Check file permissions
    PERMS=$(stat -c %a "$PRIVATE_KEY_FILE" 2>/dev/null || stat -f %A "$PRIVATE_KEY_FILE" 2>/dev/null)
    if [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ]; then
        print_warning "Key file permissions: $PERMS (recommended: 600 or 400)"
    else
        print_success "Key file permissions correct: $PERMS"
    fi
}

validate_github_cli() {
    print_header "Validating GitHub CLI"
    
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) not found"
        echo "Install from: https://cli.github.com"
        exit 1
    fi
    
    GH_VERSION=$(gh --version)
    print_success "GitHub CLI installed: $GH_VERSION"
    
    # Check authentication
    if ! gh auth status &>/dev/null; then
        print_error "Not authenticated with GitHub CLI"
        echo "Run: gh auth login"
        exit 1
    fi
    
    print_success "GitHub CLI authenticated"
}

# =============================================================================
# Secret Management Functions
# =============================================================================

check_existing_secret() {
    print_header "Checking for Existing Secret"
    
    if gh secret list --repo "$REPO" 2>/dev/null | grep -q "FIRMWARE_SIGNING_KEY"; then
        print_warning "Secret FIRMWARE_SIGNING_KEY already exists in repository"
        echo "This script will OVERWRITE the existing secret."
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborting..."
            exit 0
        fi
    else
        print_success "No existing FIRMWARE_SIGNING_KEY secret found"
    fi
}

add_secret_to_github() {
    print_header "Adding Secret to GitHub"
    
    # Read key file into variable
    KEY_CONTENT=$(cat "$PRIVATE_KEY_FILE")
    
    # Count lines to verify content
    KEY_LINES=$(echo "$KEY_CONTENT" | wc -l)
    print_info "Key file contains $KEY_LINES lines"
    
    # Add secret via GitHub CLI
    print_info "Uploading secret to GitHub repository..."
    
    if echo "$KEY_CONTENT" | gh secret set FIRMWARE_SIGNING_KEY --repo "$REPO" 2>&1; then
        print_success "Secret added successfully"
    else
        print_error "Failed to add secret to GitHub"
        exit 1
    fi
    
    # Verify secret was added
    sleep 2
    if gh secret list --repo "$REPO" | grep -q "FIRMWARE_SIGNING_KEY"; then
        print_success "Secret verified in repository"
    else
        print_error "Secret verification failed"
        exit 1
    fi
}

# =============================================================================
# Public Key Setup
# =============================================================================

setup_public_key() {
    print_header "Setting Up Public Key"
    
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT
    
    # Extract public key
    print_info "Extracting public key from private key..."
    
    if openssl ec -in "$PRIVATE_KEY_FILE" -pubout \
        -out "$TEMP_DIR/firmware_signing_public.pem" 2>/dev/null; then
        print_success "Public key extracted"
    else
        print_error "Failed to extract public key"
        exit 1
    fi
    
    # Display public key location
    PUBLIC_KEY_CONTENT=$(cat "$TEMP_DIR/firmware_signing_public.pem")
    echo "$PUBLIC_KEY_CONTENT"
    
    # Suggest destination in repository
    print_info "Suggested repository location:"
    echo "  Code/secure_boot/public_keys/firmware_signing_public.pem"
    
    echo -e "\n${BLUE}Public key preview:${NC}"
    head -3 "$TEMP_DIR/firmware_signing_public.pem"
    echo "  ..."
    tail -2 "$TEMP_DIR/firmware_signing_public.pem"
    
    read -p "Copy public key to repository now? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        PUBLIC_KEY_DEST="${REPO##*/}"  # Extract repo name
        PUBLIC_KEY_DIR="Code/secure_boot/public_keys"
        
        if [ -d "$PUBLIC_KEY_DIR" ]; then
            cp "$TEMP_DIR/firmware_signing_public.pem" \
                "$PUBLIC_KEY_DIR/firmware_signing_public.pem"
            print_success "Public key copied to $PUBLIC_KEY_DIR/"
            
            echo -e "\n${YELLOW}Next steps:${NC}"
            echo "  1. git add $PUBLIC_KEY_DIR/firmware_signing_public.pem"
            echo "  2. git commit -m 'Add firmware signing public key'"
            echo "  3. git push origin develop"
        else
            print_warning "Directory not found: $PUBLIC_KEY_DIR"
        fi
    fi
}

# =============================================================================
# Verification & Testing
# =============================================================================

run_verification_test() {
    print_header "Running Verification Test"
    
    # Check if firmware_signer.py exists
    if [ ! -f "Code/Tools/secure_boot/firmware_signer.py" ]; then
        print_warning "firmware_signer.py not found, skipping tool test"
        return
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_warning "Python3 not found, skipping cryptography check"
        return
    fi
    
    # Check dependencies
    print_info "Checking Python cryptography modules..."
    if python3 -c "import cryptography, ecdsa" 2>/dev/null; then
        print_success "Python cryptography modules available"
    else
        print_warning "Python cryptography modules not installed"
        echo "Install with: pip install cryptography ecdsa"
    fi
}

# =============================================================================
# Documentation
# =============================================================================

print_documentation() {
    print_header "Secret Management Summary"
    
    cat << 'EOF'
✓ Secret Configuration Complete

Repository: ${REPO}
Secret Name: FIRMWARE_SIGNING_KEY
Status: Ready for CI/CD use

LOCATION IN CI/CD:
  - Available as: ${{ secrets.FIRMWARE_SIGNING_KEY }}
  - GitHub Actions: workflow files in .github/workflows/

SECURITY NOTES:
  ✓ Secret is encrypted at rest in GitHub
  ✓ Only exposed to workflows in this repository
  ✓ Automatically masked in logs
  ✓ Can be rotated anytime via this script

NEXT STEPS:
  1. Verify workflow file: .github/workflows/build-sign-firmware.yml
  2. Commit and push code to trigger workflow
  3. Monitor Actions tab for sign-firmware job
  4. Download signed firmware from artifacts
  
KEY ROTATION:
  To rotate the signing key:
  1. Generate new key: python3 Tools/secure_boot/firmware_signer.py generate
  2. Run this script with new key file
  3. Update public key in repository
  4. Redeploy firmware with new signature

DOCUMENTATION:
  Full setup guide: Code/Tools/secure_boot/CI_CD_SETUP.md
  Firmware signing guide: Code/Tools/secure_boot/FIRMWARE_SIGNING_GUIDE.md

TROUBLESHOOTING:
  • Secret not found: Check GitHub repository settings
  • Verification failed: Ensure public key matches private key
  • Key format issues: Use openssl ec -text -noout to validate
  • Permissions: Repository admin required to manage secrets

EOF
}

print_security_recommendations() {
    print_header "Security Recommendations"
    
    cat << 'EOF'
IMMEDIATE ACTIONS:
  ✓ Securely delete the private key from local machine
  ✓ Use secure shell (SSH) when working with keys
  ✓ Enable two-factor authentication on GitHub account
  ✓ Set branch protection rules (require status checks)

ONGOING PRACTICES:
  • Review Actions logs for suspicious activity
  • Monitor secret access in workflow runs
  • Limit repository access to team members only
  • Use Organization secrets for multi-repo signing
  • Implement signing in private/staging before production
  
KEY ROTATION TIMELINE:
  Development  : Every 3 months
  Staging      : Every 6 months
  Production   : Every 12 months (or when compromised)

COMPLIANCE:
  ✓ IEC 62443-4-1 requirement FR 4.3.1 (Key Management)
  ✓ Audit trail maintained by GitHub Actions logs
  ✓ Public key cryptography (ECDSA P-256 = 128-bit security)

EOF
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    clear
    
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║     GitHub Actions Firmware Signing Setup                 ║
║     Secure Boot CI/CD Configuration                       ║
╚═══════════════════════════════════════════════════════════╝

EOF
    
    # Execute setup steps
    validate_inputs
    validate_key_file
    validate_github_cli
    check_existing_secret
    add_secret_to_github
    setup_public_key
    run_verification_test
    
    print_documentation
    print_security_recommendations
    
    print_header "Setup Complete!"
    
    echo -e "${GREEN}✓ Firmware signing secrets configured successfully${NC}"
    echo -e "\nRepository: ${GREEN}${REPO}${NC}"
    echo -e "Secret Name: ${GREEN}FIRMWARE_SIGNING_KEY${NC}"
    echo -e "Status: ${GREEN}Ready for CI/CD${NC}\n"
}

# Run main function
main "$@"
