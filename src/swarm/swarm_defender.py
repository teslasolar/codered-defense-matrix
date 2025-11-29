"""
SwarmDefender: Lightweight defensive AI agents for protecting against multi-AI swarm attacks
Each agent operates autonomously but coordinates with others for collective defense
"""

import asyncio
import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional, Set
import numpy as np
from datetime import datetime
import random


class DefenseMode(Enum):
    """Defense operation modes"""
    PATROL = "patrol"          # Normal monitoring
    DETECT = "detect"          # Anomaly detected
    RESPOND = "respond"        # Active response
    COORDINATE = "coordinate"  # Multi-agent coordination
    ISOLATE = "isolate"       # Network isolation


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    CATASTROPHIC = 5


@dataclass
class NetworkPacket:
    """Simulated network packet for analysis"""
    src_ip: str
    dst_ip: str
    port: int
    protocol: str
    payload_size: int
    timestamp: float
    flags: List[str]
    content_hash: str


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    threat_id: str
    threat_type: str
    indicators: List[str]
    confidence: float
    timestamp: float
    source: str


class SwarmDefender:
    """
    Lightweight defensive AI agent (1MB RAM footprint)
    Patrols network, detects anomalies, coordinates responses
    """

    def __init__(self, agent_id: str, role: str = 'patrol', memory_limit: int = 100):
        """
        Initialize SwarmDefender agent

        Args:
            agent_id: Unique agent identifier
            role: Agent role (patrol, scanner, responder, coordinator)
            memory_limit: Max memory entries (keep lightweight)
        """
        self.agent_id = agent_id
        self.role = role
        self.state = DefenseMode.PATROL
        self.threat_level = ThreatLevel.LOW

        # Lightweight memory (circular buffer)
        self.memory = deque(maxlen=memory_limit)
        self.threat_memory = deque(maxlen=50)

        # Detection parameters
        self.anomaly_threshold = 0.8
        self.swarm_detection_window = 10  # seconds
        self.min_swarm_size = 50  # minimum attackers for swarm

        # Coordination
        self.neighbors: List['SwarmDefender'] = []
        self.shared_intel: deque = deque(maxlen=20)

        # Response rules
        self.response_rules = {
            'flood': self._respond_to_flood,
            'scan': self._respond_to_scan,
            'exploit': self._respond_to_exploit,
            'swarm': self._respond_to_swarm,
            'ddos': self._respond_to_ddos
        }

        # ML model (lightweight 16-dim like VectorChain)
        self.feature_extractor = self._initialize_ml_model()

        # Metrics
        self.packets_analyzed = 0
        self.threats_detected = 0
        self.responses_initiated = 0

    def _initialize_ml_model(self) -> Dict[str, np.ndarray]:
        """Initialize lightweight ML model for threat detection"""
        return {
            'weights': np.random.randn(16, 16) * 0.1,  # 16x16 matrix (1KB)
            'bias': np.zeros(16),
            'threshold_vector': np.ones(16) * 0.7
        }

    def extract_features(self, packet: NetworkPacket) -> np.ndarray:
        """
        Extract 16-dimensional feature vector from packet

        Args:
            packet: Network packet to analyze

        Returns:
            16-dim feature vector
        """
        features = np.zeros(16)

        # Basic features (0-7)
        features[0] = hash(packet.src_ip) % 256 / 255.0  # Source IP hash
        features[1] = hash(packet.dst_ip) % 256 / 255.0  # Dest IP hash
        features[2] = packet.port / 65535.0  # Port normalized
        features[3] = packet.payload_size / 65535.0  # Payload size
        features[4] = (packet.timestamp % 3600) / 3600.0  # Time pattern
        features[5] = len(packet.flags) / 8.0  # Flag count
        features[6] = 1.0 if 'SYN' in packet.flags else 0.0  # SYN flag
        features[7] = 1.0 if 'ACK' in packet.flags else 0.0  # ACK flag

        # Behavioral features (8-15)
        recent_packets = [p for p in self.memory if isinstance(p, NetworkPacket)][-10:]
        if recent_packets:
            features[8] = len(set(p.src_ip for p in recent_packets)) / 10.0  # IP diversity
            features[9] = len(set(p.port for p in recent_packets)) / 10.0  # Port diversity
            features[10] = np.std([p.payload_size for p in recent_packets]) / 1000.0  # Size variance
            features[11] = np.mean([p.timestamp for p in recent_packets[-2:]]) if len(recent_packets) > 1 else 0  # Time delta

        # Protocol features
        protocol_map = {'TCP': 0.2, 'UDP': 0.4, 'ICMP': 0.6, 'HTTP': 0.8, 'UNKNOWN': 1.0}
        features[12] = protocol_map.get(packet.protocol, 0.5)

        # Hash-based features
        content_hash_int = int(packet.content_hash[:8], 16)
        features[13] = (content_hash_int % 1000) / 1000.0
        features[14] = (content_hash_int % 10000) / 10000.0
        features[15] = (content_hash_int % 100000) / 100000.0

        return features / (np.linalg.norm(features) + 1e-8)  # L2 normalize

    def classify_threat(self, features: np.ndarray) -> float:
        """
        Classify threat level using lightweight ML

        Args:
            features: 16-dim feature vector

        Returns:
            Threat score (0-1)
        """
        # Simple neural network forward pass
        hidden = np.tanh(np.dot(self.feature_extractor['weights'], features) +
                        self.feature_extractor['bias'])

        # Compare with threshold vector
        threat_score = np.mean(hidden > self.feature_extractor['threshold_vector'])

        return threat_score

    async def patrol(self, traffic_stream: List[NetworkPacket]) -> Dict[str, Any]:
        """
        Main patrol loop - analyze traffic for threats

        Args:
            traffic_stream: Stream of network packets

        Returns:
            Patrol report with findings
        """
        self.state = DefenseMode.PATROL
        detected_threats = []
        swarm_indicators = []

        for packet in traffic_stream:
            self.packets_analyzed += 1
            self.memory.append(packet)

            # Extract features and classify
            features = self.extract_features(packet)
            threat_score = self.classify_threat(features)

            # Check for anomaly
            if threat_score > self.anomaly_threshold:
                self.state = DefenseMode.DETECT
                threat_type = await self._identify_threat_type(packet, features)

                threat_intel = ThreatIntelligence(
                    threat_id=hashlib.md5(f"{packet.src_ip}:{packet.timestamp}".encode()).hexdigest()[:8],
                    threat_type=threat_type,
                    indicators=[packet.src_ip, str(packet.port), packet.protocol],
                    confidence=threat_score,
                    timestamp=packet.timestamp,
                    source=self.agent_id
                )

                detected_threats.append(threat_intel)
                self.threat_memory.append(threat_intel)
                self.threats_detected += 1

                # Check for swarm attack
                if await self._detect_swarm_pattern():
                    swarm_indicators.append({
                        'timestamp': packet.timestamp,
                        'unique_sources': len(set(p.src_ip for p in self.memory if isinstance(p, NetworkPacket))),
                        'packet_rate': len([p for p in self.memory if isinstance(p, NetworkPacket)
                                           and p.timestamp > packet.timestamp - self.swarm_detection_window])
                    })
                    self.state = DefenseMode.COORDINATE

        # Generate patrol report
        return {
            'agent_id': self.agent_id,
            'packets_analyzed': len(traffic_stream),
            'threats_detected': len(detected_threats),
            'threat_details': detected_threats,
            'swarm_indicators': swarm_indicators,
            'state': self.state.value,
            'threat_level': max([t.confidence for t in detected_threats], default=0)
        }

    async def _identify_threat_type(self, packet: NetworkPacket, features: np.ndarray) -> str:
        """Identify specific threat type based on packet analysis"""
        # Port scan detection
        recent_ports = [p.port for p in self.memory if isinstance(p, NetworkPacket)
                       and p.src_ip == packet.src_ip][-20:]
        if len(set(recent_ports)) > 10:
            return 'scan'

        # Flood detection
        recent_same_src = [p for p in self.memory if isinstance(p, NetworkPacket)
                          and p.src_ip == packet.src_ip
                          and p.timestamp > packet.timestamp - 1]
        if len(recent_same_src) > 100:
            return 'flood'

        # DDoS detection
        unique_sources = len(set(p.src_ip for p in self.memory if isinstance(p, NetworkPacket)))
        if unique_sources > 50 and len(self.memory) == self.memory.maxlen:
            return 'ddos'

        # Exploit detection (simplified)
        if packet.payload_size > 10000 or any(flag in packet.flags for flag in ['EXPLOIT', 'OVERFLOW']):
            return 'exploit'

        # Check for swarm
        if await self._detect_swarm_pattern():
            return 'swarm'

        return 'unknown'

    async def _detect_swarm_pattern(self) -> bool:
        """
        Detect multi-AI swarm attack patterns

        Returns:
            True if swarm pattern detected
        """
        recent_packets = [p for p in self.memory if isinstance(p, NetworkPacket)
                         and p.timestamp > time.time() - self.swarm_detection_window]

        if len(recent_packets) < self.min_swarm_size:
            return False

        # Check for coordinated behavior
        unique_sources = set(p.src_ip for p in recent_packets)
        if len(unique_sources) < self.min_swarm_size:
            return False

        # Check timing patterns (synchronized attacks)
        timestamps = [p.timestamp for p in recent_packets]
        time_deltas = np.diff(sorted(timestamps))

        # Swarms often have regular intervals
        if len(time_deltas) > 0:
            std_dev = np.std(time_deltas)
            mean_delta = np.mean(time_deltas)

            # Low standard deviation suggests coordination
            if std_dev < mean_delta * 0.1:  # Within 10% variance
                return True

        # Check for similar payloads (coordinated content)
        content_hashes = [p.content_hash for p in recent_packets]
        unique_content = len(set(content_hashes))

        # Many sources with same content = likely swarm
        if unique_content < len(unique_sources) * 0.2:  # 80% same content
            return True

        return False

    async def coordinate_response(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """
        Coordinate response with neighboring agents

        Args:
            threat: Detected threat requiring response

        Returns:
            Coordination result
        """
        self.state = DefenseMode.COORDINATE

        # Share intelligence with neighbors
        await self._share_intelligence(threat)

        # Determine response strategy
        response_type = threat.threat_type
        response_func = self.response_rules.get(response_type, self._default_response)

        # Execute coordinated response
        response_result = await response_func(threat)
        self.responses_initiated += 1

        # Update state based on response
        if response_result.get('success', False):
            self.state = DefenseMode.PATROL
            self.threat_level = ThreatLevel.LOW
        else:
            self.state = DefenseMode.ISOLATE
            self.threat_level = ThreatLevel.CRITICAL

        return {
            'agent_id': self.agent_id,
            'threat_id': threat.threat_id,
            'response_type': response_type,
            'response_result': response_result,
            'coordinated_agents': len(self.neighbors),
            'state': self.state.value
        }

    async def _share_intelligence(self, threat: ThreatIntelligence) -> None:
        """Share threat intelligence with neighboring agents"""
        self.shared_intel.append(threat)

        for neighbor in self.neighbors:
            neighbor.shared_intel.append(threat)
            # Trigger neighbor analysis
            if threat.confidence > 0.9:
                neighbor.state = DefenseMode.DETECT

    async def _respond_to_flood(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Response strategy for flood attacks"""
        return {
            'action': 'rate_limit',
            'target': threat.indicators[0],  # Source IP
            'limit': '10/s',
            'duration': 3600,
            'success': True
        }

    async def _respond_to_scan(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Response strategy for port scans"""
        return {
            'action': 'tar_pit',
            'target': threat.indicators[0],
            'delay_ms': 5000,
            'fake_services': ['ssh', 'ftp', 'telnet'],
            'success': True
        }

    async def _respond_to_exploit(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Response strategy for exploit attempts"""
        return {
            'action': 'isolate',
            'target': threat.indicators[0],
            'quarantine_duration': 7200,
            'alert_level': 'critical',
            'success': True
        }

    async def _respond_to_swarm(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Response strategy for swarm attacks"""
        # Swarm defense requires collective action
        coordinated_agents = len(self.neighbors) + 1

        return {
            'action': 'swarm_defense',
            'strategy': 'distributed_blocking',
            'participating_agents': coordinated_agents,
            'blocked_sources': len(threat.indicators),
            'null_routes_added': True,
            'success': coordinated_agents >= 3  # Need at least 3 defenders
        }

    async def _respond_to_ddos(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Response strategy for DDoS attacks"""
        return {
            'action': 'null_route',
            'targets': threat.indicators,
            'upstream_notification': True,
            'scrubbing_enabled': True,
            'success': True
        }

    async def _default_response(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Default response for unknown threats"""
        return {
            'action': 'monitor',
            'enhanced_logging': True,
            'alert_soc': True,
            'success': True
        }

    def add_neighbor(self, agent: 'SwarmDefender') -> None:
        """Add neighboring agent for coordination"""
        if agent not in self.neighbors and agent != self:
            self.neighbors.append(agent)

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            'agent_id': self.agent_id,
            'role': self.role,
            'state': self.state.value,
            'threat_level': self.threat_level.value,
            'packets_analyzed': self.packets_analyzed,
            'threats_detected': self.threats_detected,
            'responses_initiated': self.responses_initiated,
            'memory_usage': len(self.memory),
            'neighbors': len(self.neighbors),
            'shared_intel': len(self.shared_intel)
        }


class DefensiveSwarm:
    """
    Coordinated swarm of defensive agents
    """

    def __init__(self, swarm_size: int = 100):
        """
        Initialize defensive swarm

        Args:
            swarm_size: Number of defensive agents
        """
        self.swarm_size = swarm_size
        self.agents: List[SwarmDefender] = []
        self.topology = 'mesh'  # mesh, ring, star, hierarchical

        # Initialize agents
        self._initialize_swarm()

    def _initialize_swarm(self) -> None:
        """Initialize swarm agents and topology"""
        # Create agents with different roles
        roles = ['patrol'] * 70 + ['scanner'] * 20 + ['responder'] * 8 + ['coordinator'] * 2

        for i in range(self.swarm_size):
            agent = SwarmDefender(
                agent_id=f"defender_{i:03d}",
                role=roles[i] if i < len(roles) else 'patrol'
            )
            self.agents.append(agent)

        # Establish topology
        self._configure_mesh_topology()

    def _configure_mesh_topology(self) -> None:
        """Configure mesh network topology"""
        # Each agent connects to 3-5 random neighbors
        for agent in self.agents:
            num_neighbors = random.randint(3, min(5, len(self.agents) - 1))
            potential_neighbors = [a for a in self.agents if a != agent]
            neighbors = random.sample(potential_neighbors, num_neighbors)

            for neighbor in neighbors:
                agent.add_neighbor(neighbor)

    async def deploy(self, target_network: str = "10.0.0.0/8") -> Dict[str, Any]:
        """
        Deploy swarm to protect network

        Args:
            target_network: Network range to protect

        Returns:
            Deployment status
        """
        deployed_agents = []

        for agent in self.agents:
            agent.state = DefenseMode.PATROL
            deployed_agents.append({
                'agent_id': agent.agent_id,
                'role': agent.role,
                'status': 'deployed'
            })

        return {
            'swarm_size': self.swarm_size,
            'target_network': target_network,
            'topology': self.topology,
            'deployed_agents': len(deployed_agents),
            'deployment_time': datetime.now().isoformat()
        }

    async def collective_defense(self, attack_indicators: List[Dict]) -> Dict[str, Any]:
        """
        Coordinate collective defense against detected attack

        Args:
            attack_indicators: List of attack indicators

        Returns:
            Defense result
        """
        responses = []

        # Coordinators analyze and distribute tasks
        coordinators = [a for a in self.agents if a.role == 'coordinator']

        for coordinator in coordinators:
            # Create threat intelligence from indicators
            threat = ThreatIntelligence(
                threat_id=hashlib.md5(str(attack_indicators).encode()).hexdigest()[:8],
                threat_type='swarm',
                indicators=[str(ind) for ind in attack_indicators],
                confidence=0.95,
                timestamp=time.time(),
                source='collective_analysis'
            )

            # Coordinate response
            response = await coordinator.coordinate_response(threat)
            responses.append(response)

        return {
            'defense_type': 'collective',
            'participating_agents': len(self.agents),
            'responses': responses,
            'status': 'defending'
        }


# Example usage
async def main():
    """Demonstration of SwarmDefender capabilities"""
    print("Initializing CodeRED SwarmDefender System...")

    # Create defensive swarm
    swarm = DefensiveSwarm(swarm_size=10)  # Small swarm for demo

    # Deploy swarm
    deployment = await swarm.deploy("192.168.1.0/24")
    print(f"Deployed {deployment['deployed_agents']} agents")

    # Simulate network traffic (including attack)
    normal_packets = []
    attack_packets = []

    # Generate normal traffic
    for i in range(50):
        packet = NetworkPacket(
            src_ip=f"192.168.1.{random.randint(1, 254)}",
            dst_ip="192.168.1.1",
            port=random.choice([80, 443, 22, 3389]),
            protocol="TCP",
            payload_size=random.randint(100, 1500),
            timestamp=time.time() + i * 0.1,
            flags=["ACK"],
            content_hash=hashlib.md5(f"normal_{i}".encode()).hexdigest()
        )
        normal_packets.append(packet)

    # Generate swarm attack traffic
    for i in range(100):
        packet = NetworkPacket(
            src_ip=f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            dst_ip="192.168.1.1",
            port=80,
            protocol="TCP",
            payload_size=65000,  # Large payload
            timestamp=time.time() + 5 + i * 0.01,  # Rapid succession
            flags=["SYN"],
            content_hash=hashlib.md5(b"attack_payload").hexdigest()  # Same content
        )
        attack_packets.append(packet)

    # Combine traffic
    all_traffic = normal_packets + attack_packets
    random.shuffle(all_traffic)

    # Have first agent patrol
    agent = swarm.agents[0]
    report = await agent.patrol(all_traffic)

    print(f"\nPatrol Report from {report['agent_id']}:")
    print(f"  Packets Analyzed: {report['packets_analyzed']}")
    print(f"  Threats Detected: {report['threats_detected']}")
    print(f"  Swarm Indicators: {len(report['swarm_indicators'])}")

    if report['swarm_indicators']:
        print("\n⚠️  SWARM ATTACK DETECTED!")
        print(f"  Unique Sources: {report['swarm_indicators'][0]['unique_sources']}")
        print(f"  Packet Rate: {report['swarm_indicators'][0]['packet_rate']}/window")

        # Initiate collective defense
        defense_result = await swarm.collective_defense(report['swarm_indicators'])
        print(f"\n🛡️  Collective Defense Activated:")
        print(f"  Participating Agents: {defense_result['participating_agents']}")
        print(f"  Status: {defense_result['status']}")

    # Show swarm status
    print("\nSwarm Status:")
    for agent in swarm.agents[:3]:  # Show first 3 agents
        status = agent.get_status()
        print(f"  {status['agent_id']}: {status['state']} | Threats: {status['threats_detected']}")


if __name__ == "__main__":
    asyncio.run(main())