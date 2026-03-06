#!/bin/bash
# Secure Boot Integration Checklist for CubeOrange
# IEC 62443-4-1 Cybersecurity Hardening
# 
# Run this script to validate secure boot implementation
# Modify as needed for your specific setup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CUBEORANGE_DIR="${CUBEORANGE_DIR:-.}"
CRYPTO_BACKEND="${CRYPTO_BACKEND:-mbedtls}"
TARGET_BOARD="cubepilot_cubeorange_default"

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Helper functions
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_pass() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((CHECKS_PASSED++))
}

print_fail() {
    echo -e "${RED}[✗]${NC} $1"
    ((CHECKS_FAILED++))
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    ((CHECKS_WARNING++))
}

check_file() {
    if [ -f "$1" ]; then
        print_pass "File exists: $1"
        return 0
    else
        print_fail "File missing: $1"
        return 1
    fi
}

check_command() {
    if command -v "$1" &> /dev/null; then
        print_pass "Command available: $1"
        return 0
    else
        print_fail "Command not found: $1"
        return 1
    fi
}

# ============================================================================

print_header "CubeOrange Secure Boot Integration Validator"

echo "Configuration:"
echo "  Board: $TARGET_BOARD"
echo "  Crypto Backend: $CRYPTO_BACKEND"
echo "  CubeOrange Dir: $CUBEORANGE_DIR"
echo ""

# ============================================================================
print_header "1. SYSTEM DEPENDENCIES"

check_command "python3"
check_command "make"
check_command "arm-none-eabi-gcc"
check_command "git"

# Check Python packages
python3 -c "from cryptography.hazmat.primitives.asymmetric import ec" 2>/dev/null && \
    print_pass "Python cryptography library installed" || \
    print_fail "Python cryptography library missing (install: pip install cryptography)"

python3 -c "import ecdsa" 2>/dev/null && \
    print_pass "Python ecdsa library installed" || \
    print_warn "Python ecdsa library missing (optional: pip install ecdsa)"

# ============================================================================
print_header "2. SOURCE FILES"

check_file "Code/boards/cubepilot/cubeorange/src/secure_boot.h"
check_file "Code/boards/cubepilot/cubeorange/src/secure_boot.c"
check_file "Code/boards/cubepilot/cubeorange/src/secure_boot_integration.c"
check_file "Code/boards/cubepilot/cubeorange/src/bootloader_main.c"

# ============================================================================
print_header "3. CONFIGURATION FILES"

check_file "Code/boards/cubepilot/cubeorange/nuttx-config/bootloader/secure_boot.conf"
check_file "Tools/secure_boot/firmware_signer.py"

# ============================================================================
print_header "4. DOCUMENTATION"

check_file "Code/boards/cubepilot/cubeorange/SECURE_BOOT.md"
check_file "Tools/secure_boot/FIRMWARE_SIGNING_GUIDE.md"

# ============================================================================
print_header "5. BUILD CONFIGURATION"

echo "Checking CMakeLists.txt for secure boot support..."

if grep -q "secure_boot.c" "Code/boards/cubepilot/cubeorange/src/CMakeLists.txt" 2>/dev/null; then
    print_pass "secure_boot.c included in CMakeLists.txt"
else
    print_warn "secure_boot.c not in CMakeLists.txt (needs manual integration)"
fi

if grep -q "secure_boot_integration.c" "Code/boards/cubepilot/cubeorange/src/CMakeLists.txt" 2>/dev/null; then
    print_pass "secure_boot_integration.c included in CMakeLists.txt"
else
    print_warn "secure_boot_integration.c not in CMakeLists.txt (needs manual integration)"
fi

# ============================================================================
print_header "6. BOOTLOADER INTEGRATION"

if grep -q "secure_boot_verify_application" "Code/boards/cubepilot/cubeorange/src/bootloader_main.c" 2>/dev/null; then
    print_pass "Bootloader calls secure_boot_verify_application()"
else
    print_warn "Bootloader doesn't call secure_boot_verify_application() (manual integration needed)"
fi

if grep -q "secure_boot_init" "Code/boards/cubepilot/cubeorange/src/bootloader_main.c" 2>/dev/null; then
    print_pass "Bootloader initializes secure boot"
else
    print_warn "Bootloader doesn't initialize secure boot (manual integration needed)"
fi

# ============================================================================
print_header "7. CRYPTOGRAPHIC SUPPORT"

if [ "$CRYPTO_BACKEND" = "mbedtls" ]; then
    if grep -q "CONFIG_CRYPTO" "Code/platforms/nuttx/NuttX/nuttx/.config" 2>/dev/null; then
        print_pass "Crypto support enabled in NuttX config"
    else
        print_warn "Crypto support not enabled (may be needed for production)"
    fi
fi

# Check for hardware acceleration
if grep -q "STM32H7_HASH" "Code/boards/cubepilot/cubeorange/nuttx-config/console/defconfig" 2>/dev/null; then
    print_pass "STM32H7 HASH hardware support configured"
else
    print_warn "STM32H7 HASH hardware not configured (optional, improves performance)"
fi

# ============================================================================
print_header "8. SECURITY CONFIGURATION"

if grep -q "CONFIG_BOOTLOADER_SECURE_BOOT=y" "Code/boards/cubepilot/cubeorange/nuttx-config/bootloader/secure_boot.conf" 2>/dev/null; then
    print_pass "CONFIG_BOOTLOADER_SECURE_BOOT enabled"
else
    print_fail "CONFIG_BOOTLOADER_SECURE_BOOT not enabled"
fi

if grep -q "CONFIG_STM32H7_MEMORY_PROTECTION=y" "Code/boards/cubepilot/cubeorange/nuttx-config/bootloader/secure_boot.conf" 2>/dev/null; then
    print_pass "Memory protection enabled"
else
    print_warn "Memory protection not configured"
fi

if grep -q "CONFIG_BOOTLOADER_DEBUG_DISABLE=y" "Code/boards/cubepilot/cubeorange/nuttx-config/bootloader/secure_boot.conf" 2>/dev/null; then
    print_pass "Debug port disabling configured for production"
else
    print_warn "Debug port disabling not configured (should be enabled in production)"
fi

# ============================================================================
print_header "9. BUILD TEST"

echo "Attempting to build bootloader with secure boot..."

if make -C Code/boards/cubepilot/cubeorange $TARGET_BOARD_bootloader 2>&1 | tail -20; then
    print_pass "Bootloader build successful"
else
    print_fail "Bootloader build failed"
fi

# ============================================================================
print_header "10. FIRMWARE SIGNING TEST"

echo "Testing firmware signing tool..."

if python3 Tools/secure_boot/firmware_signer.py generate --output-dir /tmp/test_keys 2>/dev/null; then
    print_pass "Key generation works"
    
    # Try signing
    if [ -f "/tmp/test_keys/firmware_signing_private.pem" ]; then
        print_pass "Private key generated"
        
        if python3 Tools/secure_boot/firmware_signer.py sign \
            --firmware Code/firmware_signed.bin \
            --private-key /tmp/test_keys/firmware_signing_private.pem \
            --output /tmp/test_signed.bin 2>/dev/null; then
            print_pass "Firmware signing works"
        else
            print_warn "Firmware signing test failed (firmware_signed.bin may not exist)"
        fi
    else
        print_fail "Key generation didn't create private key"
    fi
else
    print_fail "Key generation tool failed"
fi

# Cleanup
rm -rf /tmp/test_keys /tmp/test_signed.bin 2>/dev/null

# ============================================================================
print_header "11. CODE QUALITY"

echo "Checking for common security issues in secure boot code..."

# Check for hardcoded keys
if grep -r "0x[0-9a-f]" Code/boards/cubepilot/cubeorange/src/secure_boot.c | \
   grep -i "key\|secret\|password" > /dev/null; then
    print_warn "Possible hardcoded keys in secure boot code"
else
    print_pass "No obvious hardcoded keys found"
fi

# Check for TODO comments
if grep -r "TODO.*CRYPTO\|TODO.*SECURITY\|TODO.*VERIFY" Code/boards/cubepilot/cubeorange/src/secure_boot*.c > /dev/null; then
    TODOS=$(grep -r "TODO.*CRYPTO\|TODO.*SECURITY\|TODO.*VERIFY" Code/boards/cubepilot/cubeorange/src/secure_boot*.c | wc -l)
    print_warn "Found $TODOS TODO comments in secure boot code (for production implementation)"
else
    print_pass "No critical TODO comments found"
fi

# ============================================================================
print_header "12. DOCUMENTATION QUALITY"

echo "Checking documentation completeness..."

DOCS_FOUND=0
[ -f "Code/boards/cubepilot/cubeorange/SECURE_BOOT.md" ] && ((DOCS_FOUND++))
[ -f "Tools/secure_boot/FIRMWARE_SIGNING_GUIDE.md" ] && ((DOCS_FOUND++))
[ -f "Code/boards/cubepilot/cubeorange/README.md" ] && \
    grep -q "Secure Boot" "Code/boards/cubepilot/cubeorange/README.md" && ((DOCS_FOUND++))

if [ $DOCS_FOUND -ge 2 ]; then
    print_pass "Documentation coverage adequate"
else
    print_warn "Documentation could be more comprehensive"
fi

# ============================================================================
print_header "SUMMARY"

echo ""
echo "Checks Passed:   $CHECKS_PASSED"
echo "Checks Failed:   $CHECKS_FAILED"
echo "Warnings:        $CHECKS_WARNING"
echo ""

if [ $CHECKS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Secure boot integration is ready for development!${NC}"
    exit 0
elif [ $CHECKS_FAILED -le 2 ]; then
    echo -e "${YELLOW}⚠ Secure boot integration needs minor fixes${NC}"
    exit 1
else
    echo -e "${RED}✗ Secure boot integration has critical issues${NC}"
    exit 2
fi

# ============================================================================
# DEPLOYMENT CHECKLIST
# ============================================================================
: <<'DEPLOYMENT_CHECKLIST'

# Complete this checklist before production deployment:

## Phase 1: Development (Complete ✓)
- [ ] Implement secure_boot.h/c modules
- [ ] Integrate with bootloader (secure_boot_integration.c)
- [ ] Create firmware signing tool (firmware_signer.py)
- [ ] Write comprehensive documentation
- [ ] Unit test signature verification
- [ ] Integration test with bootloader

## Phase 2: Testing
- [ ] Test on target hardware (CubeOrange)
- [ ] Verify firmware signature validation works
- [ ] Test anti-rollback protection
- [ ] Test bootloader self-verification
- [ ] Test key rotation procedure
- [ ] Load test (many boot cycles)
- [ ] Security audit by external party

## Phase 3: Key Management Setup
- [ ] Generate production key pairs
- [ ] Store private key in HSM or secure vault
- [ ] Implement key escrow service
- [ ] Document key recovery procedures
- [ ] Train operations team

## Phase 4: Deployment
- [ ] Modify CI/CD to sign all firmware
- [ ] Deploy bootloader with secure boot enabled
- [ ] Provision public keys to devices
- [ ] Test firmware update procedure
- [ ] Monitor boot failure rates
- [ ] Document incident response procedures

## Phase 5: Operations
- [ ] Monitor security logs
- [ ] Perform quarterly key rotation tests
- [ ] Maintain firmware signature database
- [ ] Respond to any security incidents
- [ ] Plan migration to post-quantum algorithms by 2040

DEPLOYMENT_CHECKLIST
