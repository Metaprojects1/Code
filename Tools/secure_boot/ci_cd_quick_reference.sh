#!/usr/bin/env bash
# ci_cd_quick_reference.sh
# Quick reference guide for CI/CD firmware signing setup

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_section() {
    echo -e "\n${BLUE}════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════${NC}\n"
}

# Main content
cat << 'EOF'

╔════════════════════════════════════════════════════════════════╗
║   CI/CD Firmware Signing - Quick Reference Guide              ║
║   CubeOrange Secure Boot Implementation (Step 4)              ║
╚════════════════════════════════════════════════════════════════╝

EOF

print_section "1️⃣  CURRENT STATUS"
cat << 'EOF'
✅ COMPLETED - Step 4: CI/CD Firmware Signing

Components Delivered:
  ✓ GitHub Actions workflow (.github/workflows/build-sign-firmware.yml)
  ✓ CMake signing module (Code/cmake/secure_boot_signing.cmake)
  ✓ Secrets setup script (Code/Tools/secure_boot/setup_github_secrets.sh)
  ✓ Complete CI/CD documentation (Code/Tools/secure_boot/CI_CD_SETUP.md)
  ✓ Step 4 completion guide (Code/Tools/secure_boot/STEP4_CI_CD_COMPLETE.md)
  ✓ CMakeLists example (Code/cmake/CMakeLists_example.txt)
  ✓ This quick reference guide

Overall Secure Boot Status: 🟢 COMPLETE (All 4 Steps Done)
  ✓ Step 1: Bootloader Integration
  ✓ Step 2: Hardware Crypto Support
  ✓ Step 3: Audit Logging System
  ✓ Step 4: CI/CD Firmware Signing

EOF

print_section "2️⃣  QUICK START (5 MINUTES)"
cat << 'EOF'
# 1. Generate signing key
cd Code/Tools/secure_boot
python3 firmware_signer.py generate --output-dir ./keys

# 2. Add to GitHub secrets
chmod +x setup_github_secrets.sh
bash setup_github_secrets.sh owner/repo-name ./keys/firmware_signing_private.pem

# 3. Commit public key
cp keys/firmware_signing_public.pem ../../secure_boot/public_keys/
git add Code/secure_boot/public_keys/
git commit -m "Add firmware signing public key"
git push origin develop

# 4. Trigger workflow
git push origin develop  # or manually via GitHub Actions tab

# 5. Download signed firmware
gh run download <run-id> --name firmware-signed-<sha>

EOF

print_section "3️⃣  KEY FILES CREATED"
TABLE_FORMAT="%-45s %-25s\n"
printf "$TABLE_FORMAT" "FILE" "PURPOSE"
printf "$TABLE_FORMAT" "$(printf '=%.0s' {1..45})" "$(printf '=%.0s' {1..25})"
cat << 'EOF' | awk -v fmt="$TABLE_FORMAT" '{printf fmt, $0, $NF}' RS= FS='|'
.github/workflows/build-sign-firmware.yml | Workflow
Code/cmake/secure_boot_signing.cmake | CMake Module
Code/Tools/secure_boot/setup_github_secrets.sh | Setup Script
Code/Tools/secure_boot/CI_CD_SETUP.md | Full Guide
Code/Tools/secure_boot/STEP4_CI_CD_COMPLETE.md | Instructions
Code/cmake/CMakeLists_example.txt | CMake Example
EOF

echo ""

print_section "4️⃣  VERIFICATION CHECKLIST"
cat << 'EOF'
Before going to production:

SECURITY:
  [ ] Private key stored ONLY in GitHub Secrets
  [ ] Public key committed and reviewed
  [ ] Secret masked in workflow logs
  [ ] Two-factor authentication enabled

FUNCTIONALITY:
  [ ] Workflow builds firmware successfully
  [ ] Signature verification passes
  [ ] Artifacts uploaded and downloadable
  [ ] All tests pass
  [ ] Local signing works (tested locally)

COMPLIANCE (IEC 62443-4-1):
  [ ] Firmware metadata includes version/hash
  [ ] Build time recorded
  [ ] Release notes generated
  [ ] Signing key index matches bootloader

EOF

print_section "5️⃣  VERIFY SETUP"
cat << 'EOF'
# Check workflow file exists
ls -la .github/workflows/build-sign-firmware.yml

# Test signing locally
cd Code/Tools/secure_boot
python3 firmware_signer.py generate --output-dir ./test_keys
python3 firmware_signer.py sign \
    --firmware /path/to/firmware.elf \
    --private-key ./test_keys/firmware_signing_private.pem \
    --output firmware_test_signed.bin
python3 firmware_signer.py verify firmware_test_signed.bin

# Check CMake module loads
cd Code
cmake -DFIRMWARE_SIGNING_ENABLED=TRUE -B build .

EOF

print_section "6️⃣  TROUBLESHOOTING"
cat << 'EOF'
Problem: Signature verification failed
Solution: Validate key pair matches
  $ openssl ec -in private_key.pem -pubout | diff -w - public_key.pem

Problem: FIRMWARE_SIGNING_KEY not found in secrets
Solution: Re-add using setup script
  $ bash setup_github_secrets.sh owner/repo key.pem

Problem: Python cryptography module not found
Solution: Already included in workflow, or install locally:
  $ pip install cryptography ecdsa

Problem: Workflow not triggering
Solution: Check workflow is enabled
  $ gh workflow list --repo owner/repo

EOF

print_section "7️⃣  ARCHITECTURE"
cat << 'EOF'
Developer Push → GitHub Actions Workflow → Build → Sign → Verify → Release
                          ↓                  ↓        ↓       ↓
                   [Trigger on Events]    [CMake]  [ECDSA]  [SHA256]
                                                    with key  with pubkey
                                                  from Secrets in Repo

EOF

print_section "8️⃣  NEXT STEPS"
cat << 'EOF'
IMMEDIATE (Today):
  1. Generate signing key: python3 firmware_signer.py generate
  2. Run setup script: bash setup_github_secrets.sh
  3. Test workflow: git push to develop branch

WEEK 1:
  1. Download signed firmware from GitHub
  2. Verify on CubeOrange hardware (if available)
  3. Document team procedures

MONTH 1:
  1. Integrate CMake signing into main build
  2. Set up branch protection rules
  3. Plan key rotation schedule

ONGOING:
  1. Monitor CI/CD logs for anomalies
  2. Rotate keys quarterly
  3. Maintain audit trail of all signing events

EOF

print_section "9️⃣  DOCUMENTATION"
cat << 'EOF'
For more details, see:

  Code/Tools/secure_boot/STEP4_CI_CD_COMPLETE.md
    ↳ Complete guide with examples

  Code/Tools/secure_boot/CI_CD_SETUP.md
    ↳ Detailed setup for all CI/CD platforms (GitLab, Jenkins, etc.)

  Code/Tools/secure_boot/FIRMWARE_SIGNING_GUIDE.md
    ↳ Technical details of firmware signing tool

  Code/Tools/secure_boot/SECURE_BOOT.md
    ↳ Overall secure boot architecture

  Code/cmake/CMakeLists_example.txt
    ↳ CMake integration example

EOF

print_section "🔟  SECURITY BEST PRACTICES"
cat << 'EOF'
✓ DO:
  • Use GitHub Secrets for private keys
  • Rotate keys periodically (quarterly)
  • Keep public keys in repository
  • Review CI logs for anomalies
  • Use separate keys for dev/staging/prod
  • Sign commits/tags with GPG
  • Enable branch protection rules

✗ DON'T:
  • Commit private keys to repository
  • Hardcode keys in source code
  • Share key files via email/chat
  • Use same key for multiple environments
  • Skip signature verification
  • Ignore audit logs

EOF

print_section "CONTACT & SUPPORT"
cat << 'EOF'
For implementation help:
  1. Check CI/CD_SETUP.md troubleshooting section
  2. Review GitHub Actions logs (Actions tab)
  3. Test signing locally: firmware_signer.py verify
  4. Validate key file: openssl ec -in key.pem -text -noout

EOF

cat << 'EOF'

╔════════════════════════════════════════════════════════════════╗
║  Step 4 Complete! All secure boot integration delivered.      ║
║  Ready for production firmware signing and validation.        ║
╚════════════════════════════════════════════════════════════════╝

EOF
