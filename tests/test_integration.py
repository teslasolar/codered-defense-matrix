"""
Integration tests for CodeRED Defense Matrix
Tests complete defensive workflows and component interactions
"""

import pytest
import asyncio
import time
import tempfile
import os
from unittest.mock import Mock, patch
import numpy as np

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

# Import all components
from src.utils.security_core import (
    AuthenticationSystem,
    SecureCommunication,
    AntiTamperingSystem,
    AuditLogger,
    ComplianceEnforcer,
    SecurityContext,
    SecurityLevel,
    AuthenticationMethod
)
from src.blockchain.vector_chain import VectorChain
from src.swarm.swarm_defender import DefensiveSwarm, NetworkPacket
from src.core.defense_matrix import DefenseMatrix, ThreatVector
from src.honeypot.honeypot_net import HoneypotNet


@pytest.mark.integration
class TestFullDefensiveFlow:
    """Test complete defensive operation flow"""

    @pytest.mark.asyncio
    async def test_authenticated_defensive_deployment(self):
        """Test full deployment with authentication and compliance"""

        # 1. Initialize security systems
        auth = AuthenticationSystem()
        compliance = ComplianceEnforcer()
        audit = AuditLogger()

        # 2. Authenticate operator
        credentials = {
            'user_id': 'defense_operator',
            'password': 'SecurePass123!',
            'totp_code': '123456',
            'source_ip': '192.168.1.100'
        }

        with patch.object(auth, '_verify_password', return_value=True):
            with patch.object(auth, '_verify_totp', return_value=True):
                context = auth.authenticate(credentials, required_factors=2)
                assert context is not None

        # 3. Check compliance for deployment
        is_compliant, reason = compliance.check_compliance(
            'deploy_defense_matrix',
            context
        )
        assert is_compliant == True

        # 4. Initialize defense components
        matrix = DefenseMatrix(shape=(100, 100, 100), sparse=True)
        swarm = DefensiveSwarm(swarm_size=10)
        chain = VectorChain(dimensions=16, nodes=50)

        # 5. Deploy defenses
        deployment_result = await swarm.deploy("192.168.0.0/16")
        assert deployment_result['deployed_agents'] == 10

        # 6. Log deployment
        audit.log_event(
            'defense_deployment',
            context,
            {
                'components': ['matrix', 'swarm', 'chain'],
                'status': 'success'
            }
        )

        # 7. Verify audit trail
        assert audit.verify_log_integrity() == True

    @pytest.mark.asyncio
    async def test_threat_detection_and_response(self):
        """Test end-to-end threat detection and response"""

        # 1. Setup honeypot network
        honeypots = HoneypotNet(honeypot_count=10)

        # 2. Simulate attack
        attack_result = await honeypots.simulate_attack('swarm', 'high')
        assert attack_result['events_generated'] > 0

        # 3. Setup defensive swarm
        swarm = DefensiveSwarm(swarm_size=5)
        await swarm.deploy("0.0.0.0/0")

        # 4. Detect attack pattern
        agent = swarm.agents[0]
        attack_traffic = self._generate_attack_traffic()
        report = await agent.patrol(attack_traffic)

        # 5. Verify with blockchain
        if report['threats_detected'] > 0:
            chain = VectorChain()
            alert = {
                'threat_type': report['threat_details'][0].threat_type,
                'confidence': report['threat_details'][0].confidence
            }

            signatures = await chain.simulate_node_signatures(alert, 0.7)
            verified = await chain.verify_alert(alert, signatures)
            assert verified == True

            # 6. Coordinate response
            response = await swarm.collective_defense([alert])
            assert response['status'] == 'defending'

    @pytest.mark.asyncio
    async def test_encrypted_component_communication(self):
        """Test secure communication between components"""

        # 1. Setup secure communication
        crypto = SecureCommunication()

        # 2. Create command from controller to swarm
        command = {
            'action': 'deploy_honeypots',
            'target_zone': 'dmz',
            'count': 20,
            'classification': 'SECRET'
        }

        # 3. Encrypt command
        encrypted_command = crypto.encrypt_message(command, SecurityLevel.SECRET)

        # 4. Verify encryption worked
        assert encrypted_command != str(command)

        # 5. Decrypt at swarm side
        decrypted, authentic = crypto.decrypt_message(encrypted_command)
        assert authentic == True
        assert decrypted == command

        # 6. Execute command
        honeypots = HoneypotNet(honeypot_count=20)
        stats = honeypots.get_statistics()
        assert stats['total_honeypots'] == 20

    @pytest.mark.asyncio
    async def test_matrix_swarm_coordination(self):
        """Test DefenseMatrix and SwarmDefender coordination"""

        # 1. Setup matrix and swarm
        matrix = DefenseMatrix(shape=(100, 100, 100), sparse=True)
        swarm = DefensiveSwarm(swarm_size=5)

        # 2. Deploy swarm to matrix positions
        positions = [(50, 50, 50), (25, 25, 25), (75, 75, 75)]
        for pos in positions:
            result = await matrix.deploy_swarm(pos, swarm_size=10)
            assert result['status'] == 'deployed'

        # 3. Simulate threat
        threat_vector = ThreatVector(
            origin=(10, 10, 10),
            direction=np.array([1, 1, 1]) / np.sqrt(3),
            magnitude=50,
            threat_type='swarm_attack',
            timestamp=time.time()
        )

        # 4. Matrix responds
        matrix_response = await matrix.respond_to_attack(threat_vector)
        assert matrix_response['status'] == 'responding'
        assert matrix_response['defenders_activated'] > 0

        # 5. Swarm coordinates
        swarm_response = await swarm.collective_defense([{
            'type': threat_vector.threat_type,
            'origin': threat_vector.origin
        }])
        assert swarm_response['participating_agents'] == 5

    @pytest.mark.asyncio
    async def test_anti_tampering_protection(self):
        """Test system integrity protection during operation"""

        # 1. Setup anti-tampering
        tamper = AntiTamperingSystem()

        # 2. Create critical files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('CRITICAL_DEFENSE_CODE = True')
            critical_file = f.name

        # 3. Establish baseline
        baseline = tamper.establish_baseline([critical_file])
        assert critical_file in baseline

        # 4. Run defensive operation
        swarm = DefensiveSwarm(swarm_size=3)
        await swarm.deploy("192.168.1.0/24")

        # 5. Verify no tampering
        valid, error = tamper.verify_integrity(critical_file)
        assert valid == True

        # 6. Simulate tampering attempt
        with open(critical_file, 'w') as f:
            f.write('MALICIOUS_CODE = True')

        # 7. Detect tampering
        valid, error = tamper.verify_integrity(critical_file)
        assert valid == False
        assert "INTEGRITY VIOLATION" in error

        # Cleanup
        os.unlink(critical_file)

    def _generate_attack_traffic(self):
        """Generate attack traffic for testing"""
        import hashlib
        import random

        traffic = []
        for i in range(50):
            packet = NetworkPacket(
                src_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                dst_ip="192.168.1.1",
                port=445,
                protocol="TCP",
                payload_size=65000,
                timestamp=time.time() + i * 0.01,
                flags=["SYN"],
                content_hash=hashlib.md5(b"attack").hexdigest()
            )
            traffic.append(packet)
        return traffic


@pytest.mark.integration
@pytest.mark.critical
class TestEmergencyResponse:
    """Test emergency response procedures"""

    @pytest.mark.asyncio
    async def test_emergency_mode_activation(self):
        """Test emergency mode for active attack response"""

        # 1. Simulate active attack detection
        honeypots = HoneypotNet(honeypot_count=50)
        await honeypots.simulate_attack('swarm', 'high')

        # 2. Get attack statistics
        stats = honeypots.get_statistics()
        assert stats['total_events'] > 0

        # 3. Emergency authentication (simulated root)
        auth = AuthenticationSystem()
        with patch('os.geteuid', return_value=0):  # Simulate root
            # Emergency context should be created
            emergency_context = SecurityContext(
                user_id='emergency_responder',
                role='incident_response',
                clearance_level=SecurityLevel.CRITICAL,
                authentication_methods=[AuthenticationMethod.PASSWORD],
                session_id='EMERGENCY_001',
                expires_at=time.time() + 3600,
                source_ip='console',
                audit_enabled=True
            )

        # 4. Deploy maximum defenses
        matrix = DefenseMatrix(shape=(200, 200, 200), sparse=True)
        swarm = DefensiveSwarm(swarm_size=100)  # Maximum swarm

        deployment = await swarm.deploy("0.0.0.0/0")
        assert deployment['deployed_agents'] == 100

        # 5. Activate all defensive measures
        chain = VectorChain(nodes=100)  # Maximum verification nodes

        # 6. Log emergency activation
        audit = AuditLogger()
        audit.log_event(
            'emergency_protocol_activated',
            emergency_context,
            {
                'reason': 'active_swarm_attack',
                'defenses_deployed': ['matrix', 'swarm', 'chain', 'honeypots'],
                'threat_level': 'CRITICAL'
            }
        )


@pytest.mark.integration
@pytest.mark.performance
class TestSystemPerformance:
    """Test system performance under load"""

    @pytest.mark.asyncio
    async def test_high_traffic_processing(self):
        """Test system can handle high traffic volume"""

        # 1. Create defensive swarm
        swarm = DefensiveSwarm(swarm_size=10)
        await swarm.deploy("0.0.0.0/0")

        # 2. Generate large traffic volume
        traffic = []
        for i in range(1000):  # 1000 packets
            packet = NetworkPacket(
                src_ip=f"192.168.{i % 255}.{(i // 255) % 255}",
                dst_ip="10.0.0.1",
                port=80,
                protocol="TCP",
                payload_size=1024,
                timestamp=time.time() + i * 0.001,
                flags=["ACK"],
                content_hash=hashlib.md5(f"packet_{i}".encode()).hexdigest()
            )
            traffic.append(packet)

        # 3. Process traffic
        start_time = time.time()
        agent = swarm.agents[0]
        report = await agent.patrol(traffic)
        elapsed = time.time() - start_time

        # 4. Verify performance
        assert report['packets_analyzed'] == 1000
        assert elapsed < 5.0  # Should process in under 5 seconds

    @pytest.mark.asyncio
    async def test_concurrent_verification(self):
        """Test blockchain can handle concurrent verifications"""

        chain = VectorChain(dimensions=16, nodes=100)

        # Create multiple alerts
        alerts = []
        for i in range(20):
            alert = {
                'id': i,
                'type': 'concurrent_test',
                'severity': 'medium'
            }
            alerts.append(alert)

        # Verify concurrently
        start_time = time.time()

        verification_tasks = []
        for alert in alerts:
            signatures = await chain.simulate_node_signatures(alert, 0.7)
            task = chain.verify_alert(alert, signatures)
            verification_tasks.append(task)

        results = await asyncio.gather(*verification_tasks)
        elapsed = time.time() - start_time

        # All should verify
        assert all(results)
        assert elapsed < 10.0  # Should complete in under 10 seconds


# Import required for tests
import hashlib

if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short', '-m', 'integration'])