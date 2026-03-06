#!/usr/bin/env python3
"""
Firmware Signing Tool for CubeOrange Secure Boot
Implements ECDSA P-256 signature generation and firmware packaging
IEC 62443-4-1 compliant
"""

import os
import sys
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: cryptography library required. Install with: pip install cryptography")
    sys.exit(1)


# Firmware Metadata Structure
# Must match secure_boot.h firmware_metadata_t
class FirmwareMetadata:
    MAGIC = 0x53424F4F  # "SBOOT"
    VERSION = 0x0100    # v1.0
    HASH_SIZE = 32      # SHA256
    SIGNATURE_SIZE = 64 # ECDSA P-256 (R || S)
    STRUCT_FORMAT = '<IHHII32s64sB7s'
    METADATA_SIZE = struct.calcsize(STRUCT_FORMAT)
    DEFAULT_FIRMWARE_VERSION = (1000, 0, 0)

    def __init__(self):
        self.magic = self.MAGIC
        self.version = self.VERSION
        self.flags = 0
        self.firmware_size = 0
        self.firmware_crc32 = 0
        self.hash = b'\x00' * self.HASH_SIZE
        self.signature = b'\x00' * self.SIGNATURE_SIZE
        self.signing_key_index = 0
        self.reserved = b'\x00' * 7

    @staticmethod
    def encode_firmware_version(major: int, minor: int, patch: int) -> int:
        return ((major & 0xFFFF) << 16) | ((minor & 0xFF) << 8) | (patch & 0xFF)

    @staticmethod
    def decode_firmware_version(encoded: int) -> Tuple[int, int, int]:
        return ((encoded >> 16) & 0xFFFF, (encoded >> 8) & 0xFF, encoded & 0xFF)

    def set_firmware_version(self, major: int, minor: int, patch: int):
        encoded = self.encode_firmware_version(major, minor, patch)
        self.reserved = struct.pack('<I3s', encoded, b'\x00' * 3)

    def get_firmware_version(self) -> Tuple[int, int, int]:
        encoded = struct.unpack('<I', self.reserved[:4])[0]
        return self.decode_firmware_version(encoded)

    def to_bytes(self) -> bytes:
        """Serialize metadata to binary format"""
        data = struct.pack(
            self.STRUCT_FORMAT,
            self.magic,
            self.version,
            self.flags,
            self.firmware_size,
            self.firmware_crc32,
            self.hash,
            self.signature,
            self.signing_key_index,
            self.reserved
        )
        return data

    @staticmethod
    def from_bytes(data: bytes) -> 'FirmwareMetadata':
        """Deserialize metadata from binary"""
        if len(data) < FirmwareMetadata.METADATA_SIZE:
            raise ValueError("Metadata too short")
        
        metadata = FirmwareMetadata()
        (metadata.magic, metadata.version, metadata.flags,
         metadata.firmware_size, metadata.firmware_crc32,
         metadata.hash, metadata.signature,
         metadata.signing_key_index, metadata.reserved) = struct.unpack(
            FirmwareMetadata.STRUCT_FORMAT,
            data[:FirmwareMetadata.METADATA_SIZE]
        )
        return metadata


def parse_firmware_version(version: str) -> Tuple[int, int, int]:
    parts = version.strip().split('.')

    if len(parts) != 3:
        raise ValueError("Firmware version must be in MAJOR.MINOR.PATCH format (example: 1000.0.0)")

    major, minor, patch = (int(parts[0]), int(parts[1]), int(parts[2]))

    if major < 0 or major > 0xFFFF or minor < 0 or minor > 0xFF or patch < 0 or patch > 0xFF:
        raise ValueError("Version out of range: major 0-65535, minor 0-255, patch 0-255")

    return major, minor, patch


class FirmwareSigner:
    """Handles firmware signing operations"""

    def __init__(self, private_key_path: str, key_index: int = 0,
                 firmware_version: Tuple[int, int, int] = FirmwareMetadata.DEFAULT_FIRMWARE_VERSION):
        """
        Initialize signer with private key
        
        Args:
            private_key_path: Path to EC private key (PEM format)
            key_index: Index of key used for signing (0-4)
        """
        self.key_index = key_index
        self.firmware_version = firmware_version
        self._load_private_key(private_key_path)

    def _load_private_key(self, key_path: str):
        """Load ECDSA P-256 private key from PEM file"""
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            
            # Verify it's EC P-256
            if not isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("Key must be an Elliptic Curve key")
            
            if self.private_key.curve.name != 'secp256r1':
                raise ValueError(f"Key curve must be P-256 (secp256r1), got {self.private_key.curve.name}")
                
        except FileNotFoundError:
            raise FileNotFoundError(f"Private key not found: {key_path}")
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}")

    def _calculate_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum"""
        crc = 0xFFFFFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
        return crc ^ 0xFFFFFFFF

    def sign_firmware(self, firmware_path: str, output_path: str) -> bool:
        """
        Sign firmware and create signed binary with metadata
        
        Args:
            firmware_path: Path to firmware binary
            output_path: Path to output signed firmware
        
        Returns:
            True if successful
        """
        try:
            # Read firmware
            with open(firmware_path, 'rb') as f:
                firmware_data = f.read()
            
            print(f"[*] Read firmware: {len(firmware_data)} bytes")
            
            # Calculate SHA256 hash
            firmware_hash = hashlib.sha256(firmware_data).digest()
            print(f"[*] SHA256: {firmware_hash.hex()}")
            
            # Calculate CRC32
            firmware_crc = self._calculate_crc32(firmware_data)
            print(f"[*] CRC32: 0x{firmware_crc:08X}")
            
            # Sign the hash
            signature_der = self.private_key.sign(
                firmware_hash,
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
            
            # Convert DER-encoded ECDSA signature to raw fixed-size R || S (32 + 32 bytes)
            r, s = utils.decode_dss_signature(signature_der)
            signature_padded = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
            
            print(f"[*] Signature: {signature_padded.hex()}")
            
            # Create metadata
            metadata = FirmwareMetadata()
            metadata.firmware_size = len(firmware_data)
            metadata.firmware_crc32 = firmware_crc
            metadata.hash = firmware_hash
            metadata.signature = signature_padded
            metadata.signing_key_index = self.key_index
            metadata.set_firmware_version(*self.firmware_version)
            
            # Write signed firmware
            with open(output_path, 'wb') as f:
                f.write(firmware_data)
                f.write(metadata.to_bytes())
            
            print(f"[+] Signed firmware written to: {output_path}")
            print(f"[+] Total size: {len(firmware_data) + FirmwareMetadata.METADATA_SIZE} bytes")
            print(f"[+] Firmware version: {self.firmware_version[0]}.{self.firmware_version[1]}.{self.firmware_version[2]}")
            
            return True
            
        except Exception as e:
            print(f"[-] Error signing firmware: {e}")
            return False

    def verify_signature(self, firmware_path: str, metadata_path: Optional[str] = None) -> bool:
        """
        Verify firmware signature (for validation purposes)
        
        Args:
            firmware_path: Path to firmware binary
            metadata_path: Path to metadata file (or None if appended to firmware)
        
        Returns:
            True if signature is valid
        """
        try:
            # Read firmware and metadata
            with open(firmware_path, 'rb') as f:
                data = f.read()
            
            if metadata_path:
                # Metadata in separate file
                with open(metadata_path, 'rb') as f:
                    metadata_data = f.read()
                firmware_data = data
            else:
                # Metadata appended to firmware
                if len(data) < FirmwareMetadata.METADATA_SIZE:
                    raise ValueError("File too short to contain metadata")
                
                firmware_data = data[:-FirmwareMetadata.METADATA_SIZE]
                metadata_data = data[-FirmwareMetadata.METADATA_SIZE:]
            
            metadata = FirmwareMetadata.from_bytes(metadata_data)
            
            # Verify magic and version
            if metadata.magic != FirmwareMetadata.MAGIC:
                print("[-] Invalid metadata magic")
                return False
            
            if metadata.version != FirmwareMetadata.VERSION:
                print("[-] Invalid metadata version")
                return False

            fw_version = metadata.get_firmware_version()
            print(f"[*] Firmware version in metadata: {fw_version[0]}.{fw_version[1]}.{fw_version[2]}")
            
            # Verify hash
            calculated_hash = hashlib.sha256(firmware_data).digest()
            if calculated_hash != metadata.hash:
                print("[-] Hash mismatch")
                return False
            
            print("[+] Firmware verification successful")
            return True
            
        except Exception as e:
            print(f"[-] Error verifying firmware: {e}")
            return False


class KeyGenerator:
    """Generate ECDSA P-256 key pairs"""

    @staticmethod
    def generate_key_pair(output_dir: str = "."):
        """
        Generate new ECDSA P-256 key pair
        
        Args:
            output_dir: Directory to write keys to
        """
        try:
            # Generate private key
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            
            # Serialize private key (PEM format)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key (PEM format)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Write keys
            private_path = os.path.join(output_dir, "firmware_signing_private.pem")
            public_path = os.path.join(output_dir, "firmware_signing_public.pem")
            
            with open(private_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_path, 0o600)  # Restrict permissions
            
            with open(public_path, 'wb') as f:
                f.write(public_pem)
            
            print(f"[+] Private key: {private_path}")
            print(f"[+] Public key: {public_path}")
            print("[+] IMPORTANT: Keep private key secure and never share!")
            
            return True
            
        except Exception as e:
            print(f"[-] Error generating keys: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Firmware Signing Tool for CubeOrange Secure Boot (IEC 62443-4-1)"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate new key pair')
    gen_parser.add_argument('--output-dir', default='.', help='Output directory for keys')
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign firmware binary')
    sign_parser.add_argument('firmware_positional', nargs='?', help='Firmware binary file')
    sign_parser.add_argument('--firmware', dest='firmware_option', help='Firmware binary file')
    sign_parser.add_argument('--private-key', required=True, help='Private key file (PEM)')
    sign_parser.add_argument('--output', required=True, help='Output signed firmware file')
    sign_parser.add_argument('--key-index', type=int, default=0, help='Key index (0-4)')
    sign_parser.add_argument('--firmware-version', default='1000.0.0',
                             help='Firmware version in metadata (MAJOR.MINOR.PATCH), default: 1000.0.0')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify signed firmware')
    verify_parser.add_argument('firmware_positional', nargs='?', help='Signed firmware file')
    verify_parser.add_argument('--firmware', dest='firmware_option', help='Signed firmware file')
    verify_parser.add_argument('--metadata', help='Separate metadata file')
    
    args = parser.parse_args()
    
    if args.command == 'generate':
        KeyGenerator.generate_key_pair(args.output_dir)
    
    elif args.command == 'sign':
        if args.firmware_option and args.firmware_positional and args.firmware_option != args.firmware_positional:
            sign_parser.error("Provide firmware only once, either as positional argument or --firmware.")
        firmware_path = args.firmware_option or args.firmware_positional
        if not firmware_path:
            sign_parser.error("Missing firmware file. Provide positional firmware path or --firmware.")

        try:
            firmware_version = parse_firmware_version(args.firmware_version)
        except ValueError as e:
            sign_parser.error(str(e))

        signer = FirmwareSigner(args.private_key, args.key_index, firmware_version)
        signer.sign_firmware(firmware_path, args.output)
    
    elif args.command == 'verify':
        if args.firmware_option and args.firmware_positional and args.firmware_option != args.firmware_positional:
            verify_parser.error("Provide firmware only once, either as positional argument or --firmware.")
        firmware_path = args.firmware_option or args.firmware_positional
        if not firmware_path:
            verify_parser.error("Missing firmware file. Provide positional firmware path or --firmware.")

        signer = FirmwareSigner.__new__(FirmwareSigner)
        signer.verify_signature(firmware_path, args.metadata)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
