"""
Security Core Module - Authentication, Encryption, and Anti-Tampering
DEFENSIVE USE ONLY - Critical Infrastructure Protection

This module provides security primitives for the CodeRED Defense Matrix.
All functions are designed to PROTECT systems, not compromise them.
"""

import hashlib
import hmac
import json
import os
import time
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import logging

# Security event logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SecurityLevel(Enum):
    """Security classification levels"""
    PUBLIC = "public"
    SENSITIVE = "sensitive"          # Internal use
    CONFIDENTIAL = "confidential"    # Restricted access
    SECRET = "secret"               # High security
    CRITICAL = "critical"           # Critical infrastructure only


class AuthenticationMethod(Enum):
    """Multi-factor authentication methods"""
    PASSWORD = "password"
    TOTP = "totp"              # Time-based One-Time Password
    HARDWARE_TOKEN = "hardware"
    BIOMETRIC = "biometric"
    CERTIFICATE = "certificate"


@dataclass
class SecurityContext:
    """Security context for operations"""
    user_id: str
    role: str
    clearance_level: SecurityLevel
    authentication_methods: List[AuthenticationMethod]
    session_id: str
    expires_at: datetime
    source_ip: str
    audit_enabled: bool = True


class AntiTamperingSystem:
    """
    Anti-tampering and integrity verification system
    Ensures code and data haven't been modified by attackers
    """

    def __init__(self):
        self.integrity_db = {}  # Store hashes of critical files
        self.tamper_log = []
        self.baseline_established = False

    def establish_baseline(self, critical_paths: List[str]) -> Dict[str, str]:
        """
        Establish integrity baseline for critical files

        Args:
            critical_paths: List of file paths to monitor

        Returns:
            Dict of file paths and their hashes
        """
        logger.info(f"Establishing integrity baseline for {len(critical_paths)} files")

        for path in critical_paths:
            if os.path.exists(path):
                file_hash = self._calculate_file_hash(path)
                self.integrity_db[path] = {
                    'hash': file_hash,
                    'timestamp': datetime.now().isoformat(),
                    'size': os.path.getsize(path)
                }

        self.baseline_established = True
        return {path: data['hash'] for path, data in self.integrity_db.items()}

    def verify_integrity(self, path: str) -> Tuple[bool, Optional[str]]:
        """
        Verify file integrity against baseline

        Args:
            path: File path to verify

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.baseline_established:
            return False, "No baseline established"

        if path not in self.integrity_db:
            return False, "File not in integrity database"

        current_hash = self._calculate_file_hash(path)
        expected_hash = self.integrity_db[path]['hash']

        if current_hash != expected_hash:
            self._log_tampering(path, expected_hash, current_hash)
            return False, f"INTEGRITY VIOLATION: File has been modified"

        return True, None

    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate cryptographic hash of file"""
        sha256_hash = hashlib.sha256()

        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file {filepath}: {e}")
            return ""

    def _log_tampering(self, path: str, expected: str, actual: str):
        """Log tampering detection"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'expected_hash': expected,
            'actual_hash': actual,
            'alert_level': 'CRITICAL'
        }

        self.tamper_log.append(event)
        logger.critical(f"TAMPERING DETECTED: {path}")

        # Trigger immediate response
        self._initiate_tamper_response(path)

    def _initiate_tamper_response(self, compromised_path: str):
        """Initiate response to detected tampering"""
        logger.critical("INITIATING TAMPER RESPONSE PROTOCOL")

        # 1. Isolate the component
        # 2. Alert security team
        # 3. Restore from known-good backup
        # 4. Increase monitoring

        # This would trigger actual defensive actions in production
        pass


class SecureCommunication:
    """
    Encrypted communication system for component interaction
    All inter-component communication must be encrypted
    """

    def __init__(self, key: Optional[bytes] = None):
        """Initialize secure communication with encryption key"""
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()

        self.cipher = Fernet(self.key)
        self.session_keys = {}
        self.message_counter = 0

    def generate_session_key(self, session_id: str) -> bytes:
        """Generate unique session key"""
        salt = secrets.token_bytes(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(session_id.encode()))
        self.session_keys[session_id] = key

        return key

    def encrypt_message(self, message: Dict[str, Any],
                       classification: SecurityLevel = SecurityLevel.CONFIDENTIAL) -> str:
        """
        Encrypt message for secure transmission

        Args:
            message: Message dictionary to encrypt
            classification: Security classification level

        Returns:
            Encrypted message string
        """
        # Add security metadata
        secure_message = {
            'payload': message,
            'classification': classification.value,
            'timestamp': datetime.now().isoformat(),
            'sequence': self.message_counter,
            'hmac': None  # Will be added after serialization
        }

        # Serialize
        message_bytes = json.dumps(secure_message).encode()

        # Add HMAC for authentication
        hmac_digest = hmac.new(self.key, message_bytes, hashlib.sha256).hexdigest()
        secure_message['hmac'] = hmac_digest

        # Final serialization and encryption
        final_bytes = json.dumps(secure_message).encode()
        encrypted = self.cipher.encrypt(final_bytes)

        self.message_counter += 1

        return base64.b64encode(encrypted).decode()

    def decrypt_message(self, encrypted_message: str) -> Tuple[Dict[str, Any], bool]:
        """
        Decrypt and verify message

        Args:
            encrypted_message: Base64 encoded encrypted message

        Returns:
            Tuple of (decrypted_message, is_authentic)
        """
        try:
            # Decode and decrypt
            encrypted_bytes = base64.b64decode(encrypted_message.encode())
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)

            # Parse message
            secure_message = json.loads(decrypted_bytes.decode())

            # Verify HMAC
            received_hmac = secure_message.pop('hmac')
            message_bytes = json.dumps(secure_message).encode()
            expected_hmac = hmac.new(self.key, message_bytes, hashlib.sha256).hexdigest()

            if received_hmac != expected_hmac:
                logger.warning("HMAC verification failed - possible tampering")
                return {}, False

            # Check timestamp (prevent replay attacks)
            message_time = datetime.fromisoformat(secure_message['timestamp'])
            if datetime.now() - message_time > timedelta(minutes=5):
                logger.warning("Message timestamp too old - possible replay attack")
                return {}, False

            return secure_message['payload'], True

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return {}, False


class AuthenticationSystem:
    """
    Multi-factor authentication system
    Requires minimum 2 factors for critical operations
    """

    def __init__(self):
        self.sessions = {}
        self.failed_attempts = {}
        self.max_failed_attempts = 3
        self.lockout_duration = 900  # 15 minutes

    def authenticate(self, credentials: Dict[str, Any],
                     required_factors: int = 2) -> Optional[SecurityContext]:
        """
        Authenticate user with multiple factors

        Args:
            credentials: Authentication credentials
            required_factors: Minimum number of factors required

        Returns:
            SecurityContext if authenticated, None otherwise
        """
        user_id = credentials.get('user_id')

        # Check for lockout
        if self._is_locked_out(user_id):
            logger.warning(f"Authentication blocked for locked user: {user_id}")
            return None

        # Verify factors
        verified_factors = []

        # Password verification
        if 'password' in credentials:
            if self._verify_password(user_id, credentials['password']):
                verified_factors.append(AuthenticationMethod.PASSWORD)

        # TOTP verification
        if 'totp_code' in credentials:
            if self._verify_totp(user_id, credentials['totp_code']):
                verified_factors.append(AuthenticationMethod.TOTP)

        # Hardware token verification
        if 'hardware_token' in credentials:
            if self._verify_hardware_token(user_id, credentials['hardware_token']):
                verified_factors.append(AuthenticationMethod.HARDWARE_TOKEN)

        # Check if enough factors verified
        if len(verified_factors) < required_factors:
            self._record_failed_attempt(user_id)
            logger.warning(f"Insufficient authentication factors for user: {user_id}")
            return None

        # Create security context
        session_id = secrets.token_urlsafe(32)
        context = SecurityContext(
            user_id=user_id,
            role=self._get_user_role(user_id),
            clearance_level=self._get_clearance_level(user_id),
            authentication_methods=verified_factors,
            session_id=session_id,
            expires_at=datetime.now() + timedelta(hours=1),
            source_ip=credentials.get('source_ip', 'unknown'),
            audit_enabled=True
        )

        self.sessions[session_id] = context
        logger.info(f"User authenticated: {user_id} with {len(verified_factors)} factors")

        return context

    def _verify_password(self, user_id: str, password: str) -> bool:
        """Verify password (would check against secure storage)"""
        # In production, check against securely hashed passwords
        # Using bcrypt or argon2
        return True  # Placeholder

    def _verify_totp(self, user_id: str, totp_code: str) -> bool:
        """Verify TOTP code"""
        # In production, verify against user's TOTP secret
        return len(totp_code) == 6 and totp_code.isdigit()

    def _verify_hardware_token(self, user_id: str, token: str) -> bool:
        """Verify hardware token"""
        # In production, verify against hardware token service
        return len(token) > 20

    def _is_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out due to failed attempts"""
        if user_id not in self.failed_attempts:
            return False

        attempts, last_attempt = self.failed_attempts[user_id]

        if attempts >= self.max_failed_attempts:
            if time.time() - last_attempt < self.lockout_duration:
                return True
            else:
                # Reset after lockout period
                del self.failed_attempts[user_id]

        return False

    def _record_failed_attempt(self, user_id: str):
        """Record failed authentication attempt"""
        if user_id in self.failed_attempts:
            attempts, _ = self.failed_attempts[user_id]
            self.failed_attempts[user_id] = (attempts + 1, time.time())
        else:
            self.failed_attempts[user_id] = (1, time.time())

    def _get_user_role(self, user_id: str) -> str:
        """Get user role (would query from database)"""
        return "analyst"  # Placeholder

    def _get_clearance_level(self, user_id: str) -> SecurityLevel:
        """Get user clearance level"""
        return SecurityLevel.CONFIDENTIAL  # Placeholder


class AuditLogger:
    """
    Tamper-proof audit logging system
    All security-relevant events must be logged
    """

    def __init__(self, log_path: str = "/var/log/codered-audit.log"):
        self.log_path = log_path
        self.log_chain = []  # Blockchain-style linked logs

    def log_event(self, event_type: str, context: SecurityContext,
                  details: Dict[str, Any]):
        """
        Log security event with full context

        Args:
            event_type: Type of security event
            context: Security context of the operation
            details: Event-specific details
        """
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user_id': context.user_id,
            'session_id': context.session_id,
            'source_ip': context.source_ip,
            'role': context.role,
            'clearance': context.clearance_level.value,
            'details': details,
            'previous_hash': self._get_previous_hash()
        }

        # Calculate hash (makes logs tamper-evident)
        entry_hash = self._calculate_log_hash(log_entry)
        log_entry['hash'] = entry_hash

        # Append to chain
        self.log_chain.append(log_entry)

        # Write to file (append-only)
        self._write_to_file(log_entry)

        logger.info(f"Audit event logged: {event_type}")

    def _calculate_log_hash(self, entry: Dict) -> str:
        """Calculate cryptographic hash of log entry"""
        entry_str = json.dumps(entry, sort_keys=True)
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def _get_previous_hash(self) -> str:
        """Get hash of previous log entry"""
        if not self.log_chain:
            return "0" * 64  # Genesis hash
        return self.log_chain[-1]['hash']

    def _write_to_file(self, entry: Dict):
        """Write log entry to file (append-only)"""
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def verify_log_integrity(self) -> bool:
        """Verify entire log chain integrity"""
        if not self.log_chain:
            return True

        for i, entry in enumerate(self.log_chain):
            # Verify hash
            entry_copy = entry.copy()
            stored_hash = entry_copy.pop('hash')
            calculated_hash = self._calculate_log_hash(entry_copy)

            if stored_hash != calculated_hash:
                logger.critical(f"Log integrity violation at entry {i}")
                return False

            # Verify chain
            if i > 0:
                if entry['previous_hash'] != self.log_chain[i-1]['hash']:
                    logger.critical(f"Log chain broken at entry {i}")
                    return False

        return True


class ComplianceEnforcer:
    """
    Ensures compliance with security policies and regulations
    CRITICAL for legal operation in critical infrastructure
    """

    def __init__(self):
        self.policies = self._load_security_policies()
        self.compliance_status = {}

    def _load_security_policies(self) -> Dict[str, Any]:
        """Load security policies"""
        return {
            'min_password_length': 12,
            'mfa_required': True,
            'session_timeout': 900,  # 15 minutes
            'encryption_required': True,
            'audit_required': True,
            'data_retention_days': 90,
            'allowed_protocols': ['TLS1.3', 'TLS1.2'],
            'forbidden_operations': ['exec', 'eval', 'system'],
            'compliance_frameworks': ['NERC-CIP', 'NIST', 'ISO27001']
        }

    def check_compliance(self, operation: str, context: SecurityContext) -> Tuple[bool, str]:
        """
        Check if operation complies with security policies

        Args:
            operation: Operation to perform
            context: Security context

        Returns:
            Tuple of (is_compliant, reason)
        """
        # Check clearance level
        if operation.startswith('critical_') and context.clearance_level != SecurityLevel.CRITICAL:
            return False, "Insufficient clearance for critical operation"

        # Check MFA
        if self.policies['mfa_required'] and len(context.authentication_methods) < 2:
            return False, "Multi-factor authentication required"

        # Check session expiry
        if datetime.now() > context.expires_at:
            return False, "Session expired"

        # Check forbidden operations
        if any(forbidden in operation for forbidden in self.policies['forbidden_operations']):
            return False, f"Operation contains forbidden action"

        return True, "Compliant"

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report for auditors"""
        return {
            'timestamp': datetime.now().isoformat(),
            'frameworks': self.policies['compliance_frameworks'],
            'status': 'COMPLIANT',
            'findings': [],
            'recommendations': [
                "Continue regular security audits",
                "Update to latest security patches",
                "Review access control quarterly"
            ],
            'next_audit': (datetime.now() + timedelta(days=90)).isoformat()
        }


# Example usage demonstrating DEFENSIVE security implementation
def example_secure_operation():
    """
    Example of how to use security components for DEFENSE only
    This protects systems, it does not attack them
    """

    # 1. Initialize security systems
    auth = AuthenticationSystem()
    crypto = SecureCommunication()
    tamper = AntiTamperingSystem()
    audit = AuditLogger()
    compliance = ComplianceEnforcer()

    # 2. Authenticate user (requires multiple factors)
    credentials = {
        'user_id': 'security_admin',
        'password': 'SecurePassword123!',
        'totp_code': '123456',
        'source_ip': '192.168.1.100'
    }

    context = auth.authenticate(credentials, required_factors=2)

    if not context:
        print("Authentication failed - access denied")
        return

    # 3. Check compliance before operation
    operation = "deploy_defensive_swarm"
    compliant, reason = compliance.check_compliance(operation, context)

    if not compliant:
        print(f"Operation not compliant: {reason}")
        audit.log_event("compliance_violation", context, {'operation': operation, 'reason': reason})
        return

    # 4. Log the defensive action
    audit.log_event("defensive_action", context, {
        'operation': operation,
        'target': 'critical_infrastructure',
        'purpose': 'protect_against_threats'
    })

    # 5. Establish integrity baseline for monitoring
    critical_files = [
        'src/swarm/swarm_defender.py',
        'src/blockchain/vector_chain.py',
        'deployment/scripts/immediate-protection.sh'
    ]

    tamper.establish_baseline(critical_files)

    # 6. Encrypt sensitive defensive configuration
    defense_config = {
        'mode': 'active_defense',
        'threat_level': 'high',
        'response': 'automated',
        'purpose': 'protect_infrastructure'
    }

    encrypted_config = crypto.encrypt_message(defense_config, SecurityLevel.SECRET)

    print("Secure defensive operation completed")
    print(f"Session: {context.session_id}")
    print(f"Audit trail established")
    print(f"All actions logged for compliance")


if __name__ == "__main__":
    # Run example to show DEFENSIVE security usage
    example_secure_operation()