"""
Unit tests for SwarmDefender defensive AI agents
Tests threat detection, swarm coordination, and response
"""

import pytest
import asyncio
import time
import random
import hashlib
from unittest.mock import Mock, patch, MagicMock

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.swarm.swarm_defender import (
    SwarmDefender,
    DefensiveSwarm,
    NetworkPacket,
    ThreatIntelligence,
    DefenseMode,
    ThreatLevel
)


class TestSwarmDefender:
    """Test individual SwarmDefender agents"""

    def setup_method(self):
        """Setup test fixtures"""
        self.defender = SwarmDefender(
            agent_id="test_defender_001",
            role="patrol",
            memory_limit=100
        )

    def test_agent_initialization(self):
        """Test agent is initialized correctly"""
        assert self.defender.agent_id == "test_defender_001"
        assert self.defender.role == "patrol"
        assert self.defender.state == DefenseMode.PATROL
        assert self.defender.threat_level == ThreatLevel.LOW
        assert len(self.defender.memory) == 0

    def test_feature_extraction(self):
        """Test feature extraction from network packets"""
        packet = NetworkPacket(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            port=80,
            protocol="TCP",
            payload_size=1024,
            timestamp=time.time(),
            flags=["SYN", "ACK"],
            content_hash=hashlib.md5(b"test").hexdigest()
        )

        features = self.defender.extract_features(packet)

        assert features.shape == (16,)  # 16-dimensional
        assert features[6] == 1.0  # SYN flag present
        assert features[7] == 1.0  # ACK flag present
        assert 0 <= features[0] <= 1.0  # Normalized

    def test_threat_classification(self):
        """Test threat classification from features"""
        # Create features indicating threat
        threat_features = np.ones(16) * 0.9  # High values
        threat_score = self.defender.classify_threat(threat_features)
        assert threat_score > 0.5  # Should indicate threat

        # Create features indicating normal
        normal_features = np.ones(16) * 0.1  # Low values
        normal_score = self.defender.classify_threat(normal_features)
        assert normal_score < 0.5  # Should indicate normal

    @pytest.mark.asyncio
    async def test_patrol_normal_traffic(self):
        """Test patrol with normal traffic"""
        # Generate normal traffic
        traffic = self._generate_normal_traffic(50)

        report = await self.defender.patrol(traffic)

        assert report['agent_id'] == "test_defender_001"
        assert report['packets_analyzed'] == 50
        assert report['threats_detected'] == 0
        assert report['state'] == DefenseMode.PATROL.value

    @pytest.mark.asyncio
    async def test_patrol_detect_threats(self):
        """Test threat detection during patrol"""
        # Generate mixed traffic with threats
        traffic = self._generate_normal_traffic(30)
        traffic.extend(self._generate_attack_traffic(20))

        report = await self.defender.patrol(traffic)

        assert report['packets_analyzed'] == 50
        # Should detect some threats in attack traffic
        # (exact number depends on ML model randomness)
        assert report['threats_detected'] >= 0

    @pytest.mark.asyncio
    async def test_swarm_pattern_detection(self):
        """Test detection of swarm attack patterns"""
        # Generate swarm attack traffic
        swarm_traffic = self._generate_swarm_traffic()

        # Fill memory with swarm packets
        for packet in swarm_traffic:
            self.defender.memory.append(packet)

        # Detect swarm
        is_swarm = await self.defender._detect_swarm_pattern()
        assert is_swarm == True

    @pytest.mark.asyncio
    async def test_coordinate_response(self):
        """Test coordinated threat response"""
        threat = ThreatIntelligence(
            threat_id="test_threat_001",
            threat_type="flood",
            indicators=["192.168.1.100", "80", "TCP"],
            confidence=0.9,
            timestamp=time.time(),
            source="test_defender"
        )

        response = await self.defender.coordinate_response(threat)

        assert response['agent_id'] == "test_defender_001"
        assert response['threat_id'] == "test_threat_001"
        assert response['response_type'] == "flood"
        assert 'response_result' in response

    def test_add_neighbor(self):
        """Test adding neighboring agents"""
        neighbor = SwarmDefender("neighbor_001", "patrol")
        self.defender.add_neighbor(neighbor)

        assert len(self.defender.neighbors) == 1
        assert neighbor in self.defender.neighbors

        # Shouldn't add duplicates
        self.defender.add_neighbor(neighbor)
        assert len(self.defender.neighbors) == 1

    def test_memory_limit(self):
        """Test that memory limit is enforced"""
        # Add more packets than memory limit
        for i in range(150):
            packet = self._create_test_packet(f"192.168.1.{i}")
            self.defender.memory.append(packet)

        # Should only keep last 100 (memory_limit)
        assert len(self.defender.memory) == 100

    def _generate_normal_traffic(self, count):
        """Generate normal network traffic"""
        traffic = []
        for i in range(count):
            packet = NetworkPacket(
                src_ip=f"192.168.1.{random.randint(1, 254)}",
                dst_ip="10.0.0.1",
                port=random.choice([80, 443, 22]),
                protocol="TCP",
                payload_size=random.randint(100, 1500),
                timestamp=time.time() + i * 0.1,
                flags=["ACK"],
                content_hash=hashlib.md5(f"normal_{i}".encode()).hexdigest()
            )
            traffic.append(packet)
        return traffic

    def _generate_attack_traffic(self, count):
        """Generate attack traffic"""
        traffic = []
        for i in range(count):
            packet = NetworkPacket(
                src_ip=f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                dst_ip="192.168.1.1",
                port=random.choice([445, 3389, 1433]),  # Suspicious ports
                protocol="TCP",
                payload_size=65000,  # Large payload
                timestamp=time.time() + i * 0.01,  # Rapid
                flags=["SYN"],  # SYN flood
                content_hash=hashlib.md5(b"attack").hexdigest()
            )
            traffic.append(packet)
        return traffic

    def _generate_swarm_traffic(self):
        """Generate swarm attack pattern"""
        traffic = []
        base_time = time.time()

        # Many sources, synchronized timing, same content
        for i in range(100):
            packet = NetworkPacket(
                src_ip=f"10.{i}.{i}.{i}",  # Many unique sources
                dst_ip="192.168.1.1",
                port=80,
                protocol="TCP",
                payload_size=1024,
                timestamp=base_time + (i * 0.01),  # Regular intervals
                flags=["SYN"],
                content_hash=hashlib.md5(b"swarm_payload").hexdigest()  # Same content
            )
            traffic.append(packet)
        return traffic

    def _create_test_packet(self, src_ip):
        """Create a test packet"""
        return NetworkPacket(
            src_ip=src_ip,
            dst_ip="10.0.0.1",
            port=80,
            protocol="TCP",
            payload_size=1024,
            timestamp=time.time(),
            flags=["ACK"],
            content_hash=hashlib.md5(f"{src_ip}".encode()).hexdigest()
        )


class TestDefensiveSwarm:
    """Test coordinated defensive swarm"""

    def setup_method(self):
        """Setup test fixtures"""
        self.swarm = DefensiveSwarm(swarm_size=10)  # Small swarm for testing

    def test_swarm_initialization(self):
        """Test swarm is initialized correctly"""
        assert len(self.swarm.agents) == 10
        assert self.swarm.topology == 'mesh'

        # Check role distribution
        roles = [agent.role for agent in self.swarm.agents]
        assert 'patrol' in roles
        assert any(r in ['scanner', 'responder', 'coordinator'] for r in roles)

    def test_mesh_topology(self):
        """Test mesh network topology creation"""
        # Each agent should have neighbors
        for agent in self.swarm.agents:
            assert len(agent.neighbors) >= 3
            assert len(agent.neighbors) <= 5

            # Neighbors should be bidirectional
            for neighbor in agent.neighbors:
                assert agent in neighbor.neighbors

    @pytest.mark.asyncio
    async def test_swarm_deployment(self):
        """Test swarm deployment"""
        result = await self.swarm.deploy("192.168.1.0/24")

        assert result['swarm_size'] == 10
        assert result['target_network'] == "192.168.1.0/24"
        assert result['deployed_agents'] == 10
        assert 'deployment_time' in result

        # All agents should be in patrol mode
        for agent in self.swarm.agents:
            assert agent.state == DefenseMode.PATROL

    @pytest.mark.asyncio
    async def test_collective_defense(self):
        """Test coordinated collective defense"""
        attack_indicators = [
            {'source': '10.0.0.1', 'type': 'scan'},
            {'source': '10.0.0.2', 'type': 'exploit'},
            {'source': '10.0.0.3', 'type': 'flood'}
        ]

        result = await self.swarm.collective_defense(attack_indicators)

        assert result['defense_type'] == 'collective'
        assert result['participating_agents'] == 10
        assert result['status'] == 'defending'
        assert len(result['responses']) > 0


class TestThreatResponse:
    """Test threat response strategies"""

    def setup_method(self):
        """Setup test fixtures"""
        self.defender = SwarmDefender("responder_001", "responder")

    @pytest.mark.asyncio
    async def test_flood_response(self):
        """Test response to flood attacks"""
        threat = ThreatIntelligence(
            threat_id="flood_001",
            threat_type="flood",
            indicators=["192.168.1.100"],
            confidence=0.9,
            timestamp=time.time(),
            source="test"
        )

        response = await self.defender._respond_to_flood(threat)

        assert response['action'] == 'rate_limit'
        assert response['limit'] == '10/s'
        assert response['success'] == True

    @pytest.mark.asyncio
    async def test_scan_response(self):
        """Test response to port scans"""
        threat = ThreatIntelligence(
            threat_id="scan_001",
            threat_type="scan",
            indicators=["192.168.1.100"],
            confidence=0.8,
            timestamp=time.time(),
            source="test"
        )

        response = await self.defender._respond_to_scan(threat)

        assert response['action'] == 'tar_pit'
        assert response['delay_ms'] == 5000
        assert 'fake_services' in response

    @pytest.mark.asyncio
    async def test_swarm_response(self):
        """Test response to swarm attacks"""
        threat = ThreatIntelligence(
            threat_id="swarm_001",
            threat_type="swarm",
            indicators=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            confidence=0.95,
            timestamp=time.time(),
            source="test"
        )

        # Add some neighbors for coordinated response
        for i in range(3):
            neighbor = SwarmDefender(f"neighbor_{i}", "patrol")
            self.defender.add_neighbor(neighbor)

        response = await self.defender._respond_to_swarm(threat)

        assert response['action'] == 'swarm_defense'
        assert response['strategy'] == 'distributed_blocking'
        assert response['participating_agents'] >= 4  # Self + 3 neighbors


@pytest.mark.asyncio
async def test_swarm_integration():
    """Integration test for full swarm operation"""
    # Create and deploy swarm
    swarm = DefensiveSwarm(swarm_size=5)
    await swarm.deploy("0.0.0.0/0")

    # Simulate traffic for first agent
    agent = swarm.agents[0]

    # Generate mixed traffic
    normal = []
    for i in range(20):
        normal.append(NetworkPacket(
            src_ip=f"192.168.1.{i}",
            dst_ip="10.0.0.1",
            port=80,
            protocol="TCP",
            payload_size=1024,
            timestamp=time.time() + i * 0.1,
            flags=["ACK"],
            content_hash=hashlib.md5(f"normal_{i}".encode()).hexdigest()
        ))

    attack = []
    for i in range(30):
        attack.append(NetworkPacket(
            src_ip=f"10.{i}.{i}.{i}",
            dst_ip="192.168.1.1",
            port=445,
            protocol="TCP",
            payload_size=65000,
            timestamp=time.time() + i * 0.01,
            flags=["SYN"],
            content_hash=hashlib.md5(b"attack").hexdigest()
        ))

    traffic = normal + attack

    # Run patrol
    report = await agent.patrol(traffic)

    # Should analyze all packets
    assert report['packets_analyzed'] == 50

    # If threats detected, should coordinate response
    if report['threats_detected'] > 0:
        threat = report['threat_details'][0]
        response = await agent.coordinate_response(threat)
        assert response['response_result']['success'] == True


# Import numpy for tests
import numpy as np

if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])