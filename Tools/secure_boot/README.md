# Secure Boot Tools for CubeOrange

## Overview

This directory contains tools and utilities for implementing firmware signature verification and secure boot on the CubeOrange flight controller. The implementation is designed for **IEC 62443-4-1** cybersecurity compliance.

### Contents

```
Tools/secure_boot/
├── README.md                      # This file
├── firmware_signer.py             # Main firmware signing tool
├── FIRMWARE_SIGNING_GUIDE.md      # Step-by-step signing instructions
├── integration_validator.sh       # Validation script for integration
└── example_keys/                  # Example key pairs (demo only)
    ├── firmware_signing_private.pem
    └── firmware_signing_public.pem
```

## Quick Start

### 1. Generate Keys (One-time)

```bash
# Generate your own ECDSA P-256 key pair
python3 firmware_signer.py generate --output-dir ./my_keys

# Keys will be created:
# - my_keys/firmware_signing_private.pem  (KEEP SECURE!)
# - my_keys/firmware_signing_public.pem   (deploy to devices)
```

### 2. Sign Firmware

```bash
# Build firmware
make cubepilot_cubeorange_default

# Sign with your private key
python3 ./Tools/secure_boot/firmware_signer.py sign \
  --firmware ./build/cubepilot_cubeorange_default/cubepilot_cubeorange_default.elf \
  --private-key ./Tools/secure_boot/firmware_signing_private.pem \
  --output cubepilot_cubeorange_defaul_signed.bin \
  --firmware-version 1000.0.0

# Result: firmware_signed.bin is ready for upload
```

### 3. Upload to Device

```bash
# Use QGroundControl or firmware uploader tool
# The bootloader will verify the signature before booting
```

# 1) Build bootloader + firmware (in your WSL/dev env)
make cubepilot_cubeorange_bootloader
make cubepilot_cubeorange_default

# 2) Sign a BIN (not ELF)
arm-none-eabi-objcopy -O binary \
  build/cubepilot_cubeorange_default/cubepilot_cubeorange_default.elf \
  build/cubepilot_cubeorange_default/cubepilot_cubeorange_default.bin

python3 ./Tools/secure_boot/firmware_signer.py sign \
  --firmware ./build/cubepilot_cubeorange_default/cubepilot_cubeorange_default.bin \
  --private-key ./Tools/secure_boot/firmware_signing_private.pem \
  --output ./build/cubepilot_cubeorange_default/cubepilot_cubeorange_default_signed.bin \
  --firmware-version 1000.0.0

# 3) Local metadata/hash sanity
python3 ./Tools/secure_boot/firmware_signer.py verify \
  --firmware ./build/cubepilot_cubeorange_default/cubepilot_cubeorange_default_signed.bin


---

**Version**: 1.0  
**Last Updated**: February 2026  
**Compliance**: IEC 62443-4-1
