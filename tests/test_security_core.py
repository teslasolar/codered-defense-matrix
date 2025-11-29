"""
Unit tests for security_core module
Tests authentication, encryption, anti-tampering, and compliance
"""

import pytest
import asyncio
import os
import tempfile
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.utils.security_core import (
    AuthenticationSystem,
    AntiTamperingSystem,
    SecureCommunication,
    AuditLogger,
    ComplianceEnforcer,
    SecurityContext,
    SecurityLevel,
    AuthenticationMethod
)


class TestAuthenticationSystem:
    """Test multi-factor authentication system"""

    def setup_method(self):
        """Setup test fixtures"""
        self.auth = AuthenticationSystem()

    def test_successful_two_factor_auth(self):
        """Test successful authentication with 2 factors"""
        credentials = {
            'user_id': 'test_user',
            'password': 'SecurePass123!',
            'totp_code': '123456',
            'source_ip': '192.168.1.100'
        }

        with patch.object(self.auth, '_verify_password', return_value=True):
            with patch.object(self.auth, '_verify_totp', return_value=True):
                context = self.auth.authenticate(credentials, required_factors=2)

                assert context is not None
                assert context.user_id == 'test_user'
                assert len(context.authentication_methods) == 2
                assert AuthenticationMethod.PASSWORD in context.authentication_methods
                assert AuthenticationMethod.TOTP in context.authentication_methods

    def test_failed_insufficient_factors(self):
        """Test authentication failure with insufficient factors"""
        credentials = {
            'user_id': 'test_user',
            'password': 'SecurePass123!',
            'source_ip': '192.168.1.100'
        }

        with patch.object(self.auth, '_verify_password', return_value=True):
            context = self.auth.authenticate(credentials, required_factors=2)

            assert context is None  # Should fail with only 1 factor

    def test_account_lockout_after_failures(self):
        """Test account lockout after multiple failed attempts"""
        credentials = {
            'user_id': 'test_user',
            'password': 'wrong_password',
            'source_ip': '192.168.1.100'
        }

        with patch.object(self.auth, '_verify_password', return_value=False):
            # Try 3 failed attempts
            for _ in range(3):
                context = self.auth.authenticate(credentials)
                assert context is None

            # Fourth attempt should be locked out
            context = self.auth.authenticate(credentials)
            assert context is None
            assert self.auth._is_locked_out('test_user') == True

    def test_session_expiry(self):
        """Test that sessions expire after timeout"""
        credentials = {
            'user_id': 'test_user',
            'password': 'SecurePass123!',
            'totp_code': '123456',
            'source_ip': '192.168.1.100'
        }

        with patch.object(self.auth, '_verify_password', return_value=True):
            with patch.object(self.auth, '_verify_totp', return_value=True):
                context = self.auth.authenticate(credentials)
                assert context is not None

                # Check session exists
                assert context.session_id in self.auth.sessions

                # Verify expiry time is set correctly
                assert context.expires_at > datetime.now()
                assert context.expires_at < datetime.now() + timedelta(hours=2)


class TestAntiTamperingSystem:
    """Test anti-tampering and integrity verification"""

    def setup_method(self):
        """Setup test fixtures"""
        self.tamper = AntiTamperingSystem()
        self.temp_dir = tempfile.mkdtemp()

    def test_establish_baseline(self):
        """Test establishing integrity baseline"""
        # Create test files
        test_file = os.path.join(self.temp_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('print("test")')

        # Establish baseline
        result = self.tamper.establish_baseline([test_file])

        assert test_file in result
        assert len(result[test_file]) == 64  # SHA256 hash length
        assert self.tamper.baseline_established == True

    def test_verify_integrity_success(self):
        """Test successful integrity verification"""
        # Create and baseline a file
        test_file = os.path.join(self.temp_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('print("test")')

        self.tamper.establish_baseline([test_file])

        # Verify integrity (should pass)
        is_valid, error = self.tamper.verify_integrity(test_file)
        assert is_valid == True
        assert error is None

    def test_detect_tampering(self):
        """Test detection of file tampering"""
        # Create and baseline a file
        test_file = os.path.join(self.temp_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('print("test")')

        self.tamper.establish_baseline([test_file])

        # Modify the file (simulate tampering)
        with open(test_file, 'w') as f:
            f.write('print("TAMPERED")')

        # Verify integrity (should fail)
        is_valid, error = self.tamper.verify_integrity(test_file)
        assert is_valid == False
        assert "INTEGRITY VIOLATION" in error
        assert len(self.tamper.tamper_log) > 0

    def test_no_baseline_verification_fails(self):
        """Test that verification fails without baseline"""
        tamper_fresh = AntiTamperingSystem()
        is_valid, error = tamper_fresh.verify_integrity('/some/file')
        assert is_valid == False
        assert "No baseline established" in error


class TestSecureCommunication:
    """Test encrypted communication system"""

    def setup_method(self):
        """Setup test fixtures"""
        self.crypto = SecureCommunication()

    def test_encrypt_decrypt_message(self):
        """Test message encryption and decryption"""
        test_message = {
            'action': 'deploy_defense',
            'target': 'critical_system',
            'priority': 'high'
        }

        # Encrypt message
        encrypted = self.crypto.encrypt_message(test_message, SecurityLevel.SECRET)
        assert encrypted != str(test_message)  # Should be encrypted
        assert len(encrypted) > 0

        # Decrypt message
        decrypted, is_authentic = self.crypto.decrypt_message(encrypted)
        assert is_authentic == True
        assert decrypted == test_message

    def test_tampered_message_detection(self):
        """Test detection of tampered messages"""
        test_message = {'action': 'test'}
        encrypted = self.crypto.encrypt_message(test_message)

        # Tamper with encrypted message
        tampered = encrypted[:-10] + 'TAMPERED!!'

        # Try to decrypt tampered message
        decrypted, is_authentic = self.crypto.decrypt_message(tampered)
        assert is_authentic == False
        assert decrypted == {}

    def test_replay_attack_prevention(self):
        """Test prevention of replay attacks"""
        test_message = {'action': 'test'}
        encrypted = self.crypto.encrypt_message(test_message)

        # Decrypt immediately (should work)
        decrypted, is_authentic = self.crypto.decrypt_message(encrypted)
        assert is_authentic == True

        # Simulate old message (replay attack)
        with patch('src.utils.security_core.datetime') as mock_datetime:
            # Set current time to 10 minutes in the future
            future_time = datetime.now() + timedelta(minutes=10)
            mock_datetime.now.return_value = future_time

            # Try to decrypt old message
            decrypted, is_authentic = self.crypto.decrypt_message(encrypted)
            assert is_authentic == False  # Should reject old message

    def test_session_key_generation(self):
        """Test unique session key generation"""
        session1 = self.crypto.generate_session_key("session_1")
        session2 = self.crypto.generate_session_key("session_2")

        assert session1 != session2  # Keys should be unique
        assert len(session1) > 0
        assert "session_1" in self.crypto.session_keys
        assert "session_2" in self.crypto.session_keys


class TestAuditLogger:
    """Test tamper-proof audit logging"""

    def setup_method(self):
        """Setup test fixtures"""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.audit = AuditLogger(self.temp_file.name)
        self.test_context = SecurityContext(
            user_id='test_user',
            role='analyst',
            clearance_level=SecurityLevel.CONFIDENTIAL,
            authentication_methods=[AuthenticationMethod.PASSWORD],
            session_id='test_session',
            expires_at=datetime.now() + timedelta(hours=1),
            source_ip='192.168.1.100'
        )

    def test_log_event(self):
        """Test logging security events"""
        self.audit.log_event(
            'test_action',
            self.test_context,
            {'detail': 'test detail'}
        )

        assert len(self.audit.log_chain) == 1
        log_entry = self.audit.log_chain[0]

        assert log_entry['event_type'] == 'test_action'
        assert log_entry['user_id'] == 'test_user'
        assert log_entry['hash'] is not None
        assert len(log_entry['hash']) == 64  # SHA256

    def test_log_chain_integrity(self):
        """Test blockchain-style log chain integrity"""
        # Log multiple events
        for i in range(5):
            self.audit.log_event(
                f'action_{i}',
                self.test_context,
                {'index': i}
            )

        # Verify chain integrity
        assert self.audit.verify_log_integrity() == True

        # Each log should reference previous
        for i in range(1, len(self.audit.log_chain)):
            current = self.audit.log_chain[i]
            previous = self.audit.log_chain[i-1]
            assert current['previous_hash'] == previous['hash']

    def test_tampered_log_detection(self):
        """Test detection of tampered logs"""
        # Log events
        self.audit.log_event('action1', self.test_context, {})
        self.audit.log_event('action2', self.test_context, {})

        # Tamper with a log entry
        self.audit.log_chain[0]['user_id'] = 'TAMPERED_USER'

        # Verify should fail
        assert self.audit.verify_log_integrity() == False

    def test_append_only_file_writing(self):
        """Test that logs are written to file"""
        self.audit.log_event('test', self.test_context, {'data': 'test'})

        # Read the log file
        with open(self.temp_file.name, 'r') as f:
            content = f.read()

        assert 'test' in content
        assert 'test_user' in content
        log_data = json.loads(content.strip())
        assert log_data['event_type'] == 'test'


class TestComplianceEnforcer:
    """Test compliance and policy enforcement"""

    def setup_method(self):
        """Setup test fixtures"""
        self.compliance = ComplianceEnforcer()
        self.test_context = SecurityContext(
            user_id='test_user',
            role='analyst',
            clearance_level=SecurityLevel.CONFIDENTIAL,
            authentication_methods=[AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP],
            session_id='test_session',
            expires_at=datetime.now() + timedelta(hours=1),
            source_ip='192.168.1.100'
        )

    def test_compliance_check_success(self):
        """Test successful compliance check"""
        is_compliant, reason = self.compliance.check_compliance(
            'normal_operation',
            self.test_context
        )

        assert is_compliant == True
        assert reason == "Compliant"

    def test_insufficient_clearance_rejection(self):
        """Test rejection of operation with insufficient clearance"""
        is_compliant, reason = self.compliance.check_compliance(
            'critical_infrastructure_modification',
            self.test_context
        )

        assert is_compliant == False
        assert "Insufficient clearance" in reason

    def test_mfa_requirement_enforcement(self):
        """Test MFA requirement enforcement"""
        # Create context with only 1 factor
        weak_context = SecurityContext(
            user_id='test_user',
            role='analyst',
            clearance_level=SecurityLevel.CONFIDENTIAL,
            authentication_methods=[AuthenticationMethod.PASSWORD],  # Only 1 factor
            session_id='test_session',
            expires_at=datetime.now() + timedelta(hours=1),
            source_ip='192.168.1.100'
        )

        is_compliant, reason = self.compliance.check_compliance(
            'sensitive_operation',
            weak_context
        )

        assert is_compliant == False
        assert "Multi-factor authentication required" in reason

    def test_session_expiry_enforcement(self):
        """Test session expiry enforcement"""
        # Create expired context
        expired_context = SecurityContext(
            user_id='test_user',
            role='analyst',
            clearance_level=SecurityLevel.CONFIDENTIAL,
            authentication_methods=[AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP],
            session_id='test_session',
            expires_at=datetime.now() - timedelta(hours=1),  # Expired
            source_ip='192.168.1.100'
        )

        is_compliant, reason = self.compliance.check_compliance(
            'any_operation',
            expired_context
        )

        assert is_compliant == False
        assert "Session expired" in reason

    def test_forbidden_operations_blocked(self):
        """Test blocking of forbidden operations"""
        # Try to execute forbidden operation
        is_compliant, reason = self.compliance.check_compliance(
            'exec_system_command',  # Contains 'exec' which is forbidden
            self.test_context
        )

        assert is_compliant == False
        assert "forbidden action" in reason

    def test_compliance_report_generation(self):
        """Test generation of compliance reports"""
        report = self.compliance.generate_compliance_report()

        assert report['status'] == 'COMPLIANT'
        assert 'NERC-CIP' in report['frameworks']
        assert 'timestamp' in report
        assert 'next_audit' in report
        assert len(report['recommendations']) > 0


# Integration test for the security system
@pytest.mark.asyncio
async def test_full_security_flow():
    """Test complete security flow from auth to audit"""

    # 1. Initialize all systems
    auth = AuthenticationSystem()
    crypto = SecureCommunication()
    tamper = AntiTamperingSystem()
    audit = AuditLogger()
    compliance = ComplianceEnforcer()

    # 2. Authenticate user
    credentials = {
        'user_id': 'security_admin',
        'password': 'SecurePassword123!',
        'totp_code': '123456',
        'source_ip': '192.168.1.100'
    }

    with patch.object(auth, '_verify_password', return_value=True):
        with patch.object(auth, '_verify_totp', return_value=True):
            context = auth.authenticate(credentials, required_factors=2)
            assert context is not None

    # 3. Check compliance
    operation = "deploy_defensive_swarm"
    is_compliant, reason = compliance.check_compliance(operation, context)
    assert is_compliant == True

    # 4. Log action
    audit.log_event("defensive_action", context, {
        'operation': operation,
        'target': 'critical_infrastructure',
        'purpose': 'protect_against_threats'
    })
    assert len(audit.log_chain) == 1

    # 5. Encrypt sensitive data
    defense_config = {
        'mode': 'active_defense',
        'threat_level': 'high'
    }
    encrypted = crypto.encrypt_message(defense_config, SecurityLevel.SECRET)
    assert encrypted is not None

    # 6. Verify everything worked
    decrypted, authentic = crypto.decrypt_message(encrypted)
    assert authentic == True
    assert decrypted == defense_config
    assert audit.verify_log_integrity() == True


if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, '-v', '--tb=short'])