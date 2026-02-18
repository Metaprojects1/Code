# CI/CD Firmware Signing Setup Guide

## Overview

This guide walks through setting up automated firmware signing in CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins) with proper secrets management for CubeOrange secure boot implementation per IEC 62443-4-1.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CI/CD Pipeline                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. Checkout Code ──► 2. Build Firmware ──┐                 │
│       ↓                     ↓               │                 │
│  [GIT]             [CMake/Make]            │                 │
│                                             ▼                 │
│                              3. Sign Firmware                │
│                                     │                        │
│                              [firmware_signer.py]            │
│                                     │                        │
│                    Private Key ────┬─┴─────► Signed Binary   │
│                   (from secrets)   │                         │
│                                     ▼                        │
│                              4. Verify Signature            │
│                                     │                        │
│                    Public Key ─────┤                        │
│                   (in repo)         │                        │
│                                     ▼                        │
│                            5. Upload Artifacts              │
│                                     │                        │
│                    ┌────────────────┼────────────────┐      │
│                    ▼                ▼                ▼       │
│            [Releases]         [Artifacts]      [Container]  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- GitHub account with admin access to repository settings
- Python 3.8+
- `cryptography` and `ecdsa` Python packages
- Generated signing key pair (ECDSA P-256)

## Step 1: Generate Firmware Signing Key Pair

### Local Key Generation (Development/Testing)

```bash
# Generate private key (ECDSA P-256)
openssl ecparam -name prime256v1 -genkey -noout -out firmware_signing_private.pem

# Extract public key for verification
openssl ec -in firmware_signing_private.pem -pubout -out firmware_signing_public.pem

# Verify key format
openssl ec -in firmware_signing_private.pem -text -noout
```

## References

- [GitHub Secrets Documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [ECDSA RFC 6090](https://tools.ietf.org/html/rfc6090)
- [IEC 62443-4-1 Standard](https://webstore.iec.ch/publication/26959)

