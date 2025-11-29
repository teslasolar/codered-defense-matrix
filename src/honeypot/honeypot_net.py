"""
HoneypotNet: Deception infrastructure for early attack detection
Deploys fake targets to detect and analyze attack patterns
"""

import asyncio
import json
import random
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Set
from enum import Enum
from collections import defaultdict, deque
import ipaddress
from datetime import datetime


class ServiceType(Enum):
    """Honeypot service types"""
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    TELNET = "telnet"
    FTP = "ftp"
    MODBUS = "modbus"         # Industrial protocol
    DNP3 = "dnp3"             # Industrial protocol
    IEC61850 = "iec61850"     # Power grid protocol
    MQTT = "mqtt"             # IoT protocol
    COAP = "coap"             # IoT protocol
    RDP = "rdp"               # Remote Desktop
    VNC = "vnc"               # Remote control
    SMB = "smb"               # File sharing
    DATABASE = "database"      # MySQL/PostgreSQL


class HoneypotType(Enum):
    """Types of honeypots"""
    LOW_INTERACTION = "low"      # Simple port listeners
    MEDIUM_INTERACTION = "medium" # Simulated services
    HIGH_INTERACTION = "high"    # Full system emulation
    INDUSTRIAL = "industrial"     # SCADA/ICS specific
    IOT = "iot"                  # IoT device emulation


@dataclass
class HoneypotNode:
    """Individual honeypot instance"""
    honeypot_id: str
    ip_address: str
    hostname: str
    services: List[ServiceType]
    honeypot_type: HoneypotType
    deployed_time: float
    trap_log: List[Dict]
    interaction_level: str
    emulated_system: str
    location: str
    criticality: str


@dataclass
class AttackSession:
    """Tracked attack session"""
    session_id: str
    attacker_ip: str
    honeypot_id: str
    start_time: float
    end_time: Optional[float]
    commands: List[str]
    files_uploaded: List[str]
    exploitation_attempts: List[str]
    threat_score: float


class HoneypotNet:
    """
    Distributed honeypot network for deception and early warning
    """

    def __init__(self, honeypot_count: int = 1000):
        """
        Initialize HoneypotNet

        Args:
            honeypot_count: Number of honeypots to deploy
        """
        self.honeypot_count = honeypot_count
        self.honeypots: Dict[str, HoneypotNode] = {}
        self.attack_sessions: Dict[str, AttackSession] = {}
        self.alerts = asyncio.Queue(maxsize=10000)

        # Attack pattern analysis
        self.attack_patterns: deque = deque(maxlen=1000)
        self.attacker_profiles: Dict[str, Dict] = defaultdict(dict)
        self.swarm_indicators: List[Dict] = []

        # Network topology
        self.network_segments = self._generate_network_topology()

        # Industrial control systems
        self.ics_honeypots: List[str] = []
        self.iot_honeypots: List[str] = []

        # Initialize honeypots
        self._initialize_honeypots()

    def _generate_network_topology(self) -> Dict[str, Dict]:
        """Generate realistic network topology"""
        segments = {
            'corporate': {
                'subnet': '192.168.1.0/24',
                'services': [ServiceType.HTTP, ServiceType.HTTPS, ServiceType.SSH, ServiceType.RDP],
                'count': 300
            },
            'industrial': {
                'subnet': '10.10.0.0/16',
                'services': [ServiceType.MODBUS, ServiceType.DNP3, ServiceType.IEC61850],
                'count': 200
            },
            'iot': {
                'subnet': '172.16.0.0/12',
                'services': [ServiceType.MQTT, ServiceType.COAP, ServiceType.HTTP],
                'count': 400
            },
            'dmz': {
                'subnet': '203.0.113.0/24',  # Documentation range
                'services': [ServiceType.HTTP, ServiceType.HTTPS, ServiceType.FTP],
                'count': 100
            }
        }
        return segments

    def _initialize_honeypots(self) -> None:
        """Initialize honeypot instances"""
        honeypot_id = 0

        for segment_name, segment_info in self.network_segments.items():
            subnet = ipaddress.ip_network(segment_info['subnet'])
            available_ips = list(subnet.hosts())
            random.shuffle(available_ips)

            for i in range(min(segment_info['count'], len(available_ips), self.honeypot_count - honeypot_id)):
                hp_id = f"HP-{segment_name.upper()}-{honeypot_id:04d}"

                # Determine honeypot type based on segment
                if segment_name == 'industrial':
                    hp_type = HoneypotType.INDUSTRIAL
                    emulated_system = random.choice([
                        'Siemens S7-1200 PLC',
                        'Allen-Bradley ControlLogix',
                        'Schneider Modicon M580',
                        'ABB AC500 PLC'
                    ])
                    self.ics_honeypots.append(hp_id)
                elif segment_name == 'iot':
                    hp_type = HoneypotType.IOT
                    emulated_system = random.choice([
                        'Smart Thermostat',
                        'IP Camera',
                        'Smart Meter',
                        'Industrial Sensor'
                    ])
                    self.iot_honeypots.append(hp_id)
                else:
                    hp_type = random.choice([
                        HoneypotType.LOW_INTERACTION,
                        HoneypotType.MEDIUM_INTERACTION,
                        HoneypotType.HIGH_INTERACTION
                    ])
                    emulated_system = random.choice([
                        'Windows Server 2019',
                        'Ubuntu 20.04',
                        'CentOS 8',
                        'FreeBSD 13'
                    ])

                honeypot = HoneypotNode(
                    honeypot_id=hp_id,
                    ip_address=str(available_ips[i]),
                    hostname=f"{segment_name}-{emulated_system.replace(' ', '-').lower()}-{i}",
                    services=random.sample(segment_info['services'],
                                         k=random.randint(1, len(segment_info['services']))),
                    honeypot_type=hp_type,
                    deployed_time=time.time(),
                    trap_log=[],
                    interaction_level=hp_type.value,
                    emulated_system=emulated_system,
                    location=f"Zone-{segment_name}",
                    criticality=random.choice(['low', 'medium', 'high', 'critical'])
                )

                self.honeypots[hp_id] = honeypot
                honeypot_id += 1

                if honeypot_id >= self.honeypot_count:
                    break

    async def monitor(self) -> None:
        """
        Main monitoring loop for all honeypots

        Continuously monitors honeypot activity and generates alerts
        """
        while True:
            # Check each honeypot for activity
            for hp_id, honeypot in self.honeypots.items():
                if honeypot.trap_log:
                    # Analyze trapped activity
                    analysis = await self._analyze_activity(honeypot)

                    if analysis['threat_detected']:
                        alert = {
                            'alert_id': hashlib.md5(f"{hp_id}:{time.time()}".encode()).hexdigest()[:12],
                            'timestamp': datetime.now().isoformat(),
                            'honeypot_id': hp_id,
                            'honeypot_ip': honeypot.ip_address,
                            'threat_type': analysis['threat_type'],
                            'attacker_ip': analysis.get('attacker_ip', 'unknown'),
                            'confidence': analysis['confidence'],
                            'details': analysis['details']
                        }

                        await self.alerts.put(alert)

                        # Check for swarm patterns
                        if await self._detect_swarm_pattern(honeypot):
                            swarm_alert = {
                                'type': 'SWARM_DETECTED',
                                'timestamp': datetime.now().isoformat(),
                                'affected_honeypots': await self._get_affected_honeypots(),
                                'pattern': analysis['pattern']
                            }
                            await self.alerts.put(swarm_alert)

            await asyncio.sleep(1)  # Check every second

    async def _analyze_activity(self, honeypot: HoneypotNode) -> Dict[str, Any]:
        """
        Analyze honeypot activity for threats

        Args:
            honeypot: Honeypot to analyze

        Returns:
            Analysis results
        """
        if not honeypot.trap_log:
            return {'threat_detected': False}

        # Aggregate recent activity
        recent_activity = honeypot.trap_log[-100:]  # Last 100 events

        # Pattern analysis
        threat_indicators = {
            'scanning': 0,
            'exploitation': 0,
            'lateral_movement': 0,
            'data_exfiltration': 0,
            'persistence': 0
        }

        attacker_ips = set()
        commands_executed = []
        files_accessed = []

        for event in recent_activity:
            attacker_ips.add(event.get('source_ip', 'unknown'))

            # Scan detection
            if event.get('event_type') == 'port_scan':
                threat_indicators['scanning'] += 1

            # Exploitation attempts
            if event.get('event_type') in ['exploit_attempt', 'buffer_overflow', 'sql_injection']:
                threat_indicators['exploitation'] += 1

            # Command execution
            if 'command' in event:
                commands_executed.append(event['command'])
                # Check for lateral movement indicators
                if any(cmd in event['command'].lower() for cmd in ['ssh', 'rdp', 'psexec', 'wmic']):
                    threat_indicators['lateral_movement'] += 1

            # File operations
            if 'file' in event:
                files_accessed.append(event['file'])
                # Check for data exfiltration
                if event.get('operation') in ['download', 'copy', 'transfer']:
                    threat_indicators['data_exfiltration'] += 1

            # Persistence mechanisms
            if event.get('event_type') in ['registry_modification', 'service_creation', 'scheduled_task']:
                threat_indicators['persistence'] += 1

        # Calculate threat score
        threat_score = sum(threat_indicators.values()) / max(len(recent_activity), 1)

        # Determine threat type
        threat_type = max(threat_indicators, key=threat_indicators.get)

        # Build analysis result
        analysis = {
            'threat_detected': threat_score > 0.1,
            'threat_type': threat_type,
            'threat_score': threat_score,
            'confidence': min(threat_score * 2, 1.0),  # Scale confidence
            'attacker_ip': list(attacker_ips)[0] if attacker_ips else 'unknown',
            'attacker_ips': list(attacker_ips),
            'commands_executed': commands_executed[:10],  # Top 10
            'files_accessed': files_accessed[:10],
            'details': {
                'indicators': threat_indicators,
                'event_count': len(recent_activity),
                'unique_attackers': len(attacker_ips)
            },
            'pattern': self._identify_attack_pattern(threat_indicators)
        }

        # Update attacker profile
        for ip in attacker_ips:
            self._update_attacker_profile(ip, analysis)

        return analysis

    def _identify_attack_pattern(self, indicators: Dict[str, int]) -> str:
        """Identify attack pattern from indicators"""
        patterns = {
            'reconnaissance': indicators['scanning'] > 5,
            'initial_access': indicators['exploitation'] > 2,
            'execution': len([k for k, v in indicators.items() if v > 0]) > 3,
            'persistence': indicators['persistence'] > 1,
            'lateral_movement': indicators['lateral_movement'] > 2,
            'collection': indicators['data_exfiltration'] > 1,
            'exfiltration': indicators['data_exfiltration'] > 3,
            'impact': sum(indicators.values()) > 20
        }

        # Return most likely pattern
        for pattern, detected in patterns.items():
            if detected:
                return pattern

        return 'unknown'

    async def _detect_swarm_pattern(self, honeypot: HoneypotNode) -> bool:
        """
        Detect coordinated swarm attack patterns

        Args:
            honeypot: Honeypot to check

        Returns:
            True if swarm pattern detected
        """
        # Get all recent activity across all honeypots
        time_window = 10  # seconds
        current_time = time.time()

        affected_honeypots = []
        unique_attackers = set()

        for hp_id, hp in self.honeypots.items():
            recent_events = [e for e in hp.trap_log
                           if e.get('timestamp', 0) > current_time - time_window]

            if recent_events:
                affected_honeypots.append(hp_id)
                for event in recent_events:
                    unique_attackers.add(event.get('source_ip', 'unknown'))

        # Swarm indicators
        swarm_detected = (
            len(affected_honeypots) > 10 and  # Multiple honeypots hit
            len(unique_attackers) > 50 and    # Many unique sources
            len(affected_honeypots) / len(unique_attackers) > 0.2  # Coordinated targeting
        )

        if swarm_detected:
            self.swarm_indicators.append({
                'timestamp': current_time,
                'affected_count': len(affected_honeypots),
                'attacker_count': len(unique_attackers),
                'honeypots': affected_honeypots[:20]  # First 20
            })

        return swarm_detected

    async def _get_affected_honeypots(self) -> List[str]:
        """Get list of honeypots currently under attack"""
        affected = []
        current_time = time.time()

        for hp_id, honeypot in self.honeypots.items():
            recent_activity = [e for e in honeypot.trap_log
                             if e.get('timestamp', 0) > current_time - 60]
            if recent_activity:
                affected.append(hp_id)

        return affected

    def _update_attacker_profile(self, attacker_ip: str, analysis: Dict) -> None:
        """Update attacker behavioral profile"""
        profile = self.attacker_profiles[attacker_ip]

        # Update profile
        profile['last_seen'] = time.time()
        profile['threat_score'] = max(profile.get('threat_score', 0), analysis['threat_score'])
        profile['attack_count'] = profile.get('attack_count', 0) + 1
        profile['patterns'] = profile.get('patterns', [])
        profile['patterns'].append(analysis['pattern'])
        profile['targeted_honeypots'] = profile.get('targeted_honeypots', set())
        profile['targeted_honeypots'].add(analysis.get('honeypot_id'))

    async def simulate_attack(self, attack_type: str = 'random',
                            intensity: str = 'medium') -> Dict[str, Any]:
        """
        Simulate attack for testing

        Args:
            attack_type: Type of attack to simulate
            intensity: Attack intensity (low/medium/high)

        Returns:
            Simulation results
        """
        intensity_map = {'low': 10, 'medium': 50, 'high': 200}
        event_count = intensity_map.get(intensity, 50)

        # Select target honeypots
        if attack_type == 'targeted':
            # Target critical industrial systems
            targets = random.sample(self.ics_honeypots,
                                  k=min(len(self.ics_honeypots), 5))
        elif attack_type == 'swarm':
            # Target many honeypots simultaneously
            targets = random.sample(list(self.honeypots.keys()),
                                  k=min(len(self.honeypots), event_count))
        else:
            # Random targets
            targets = random.sample(list(self.honeypots.keys()),
                                  k=min(len(self.honeypots), 10))

        # Generate attack events
        events_generated = 0
        for hp_id in targets:
            honeypot = self.honeypots[hp_id]

            for _ in range(random.randint(1, 10)):
                event = self._generate_attack_event(attack_type)
                event['timestamp'] = time.time()
                event['source_ip'] = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

                honeypot.trap_log.append(event)
                events_generated += 1

        return {
            'simulation': 'complete',
            'attack_type': attack_type,
            'intensity': intensity,
            'targets_hit': len(targets),
            'events_generated': events_generated,
            'honeypots_affected': targets[:10]  # First 10
        }

    def _generate_attack_event(self, attack_type: str) -> Dict[str, Any]:
        """Generate simulated attack event"""
        event_templates = {
            'scan': {
                'event_type': 'port_scan',
                'ports_scanned': random.sample(range(1, 65535), k=100),
                'scan_type': random.choice(['SYN', 'ACK', 'FIN', 'XMAS'])
            },
            'exploit': {
                'event_type': 'exploit_attempt',
                'vulnerability': random.choice([
                    'CVE-2021-44228',  # Log4j
                    'CVE-2021-34527',  # PrintNightmare
                    'CVE-2020-1472',   # Zerologon
                    'CVE-2019-0708'    # BlueKeep
                ]),
                'payload_size': random.randint(1000, 50000)
            },
            'lateral': {
                'event_type': 'lateral_movement',
                'command': random.choice([
                    'psexec \\\\target -u admin -p pass cmd',
                    'wmic /node:target process call create cmd.exe',
                    'ssh admin@192.168.1.100',
                    'rdp://192.168.1.50'
                ])
            },
            'swarm': {
                'event_type': 'coordinated_attack',
                'coordination_id': hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
                'attack_vector': random.choice(['ddos', 'botnet', 'distributed_scan'])
            },
            'random': {
                'event_type': random.choice(['scan', 'exploit', 'command', 'download']),
                'details': 'Random attack simulation'
            }
        }

        return event_templates.get(attack_type, event_templates['random'])

    def get_statistics(self) -> Dict[str, Any]:
        """Get honeypot network statistics"""
        total_events = sum(len(hp.trap_log) for hp in self.honeypots.values())
        active_honeypots = sum(1 for hp in self.honeypots.values() if hp.trap_log)

        # Service distribution
        service_count = defaultdict(int)
        for honeypot in self.honeypots.values():
            for service in honeypot.services:
                service_count[service.value] += 1

        # Honeypot type distribution
        type_count = defaultdict(int)
        for honeypot in self.honeypots.values():
            type_count[honeypot.honeypot_type.value] += 1

        return {
            'total_honeypots': len(self.honeypots),
            'active_honeypots': active_honeypots,
            'total_events': total_events,
            'unique_attackers': len(self.attacker_profiles),
            'swarm_detections': len(self.swarm_indicators),
            'alerts_pending': self.alerts.qsize(),
            'honeypot_types': dict(type_count),
            'service_distribution': dict(service_count),
            'network_segments': {
                name: info['count']
                for name, info in self.network_segments.items()
            },
            'critical_systems': {
                'industrial': len(self.ics_honeypots),
                'iot': len(self.iot_honeypots)
            }
        }


# Example usage
async def main():
    """Demonstration of HoneypotNet capabilities"""
    print("Initializing CodeRED HoneypotNet Deception System...")

    # Create honeypot network
    honeypot_net = HoneypotNet(honeypot_count=100)  # 100 honeypots for demo

    # Start monitoring (in background)
    monitor_task = asyncio.create_task(honeypot_net.monitor())

    # Show deployment
    stats = honeypot_net.get_statistics()
    print(f"\nDeployed {stats['total_honeypots']} honeypots")
    print(f"  Industrial: {stats['critical_systems']['industrial']}")
    print(f"  IoT: {stats['critical_systems']['iot']}")
    print(f"  Services: {', '.join(stats['service_distribution'].keys())}")

    # Simulate normal activity
    print("\nSimulating normal activity...")
    await honeypot_net.simulate_attack('random', 'low')
    await asyncio.sleep(1)

    # Simulate swarm attack
    print("\n⚠️  Simulating SWARM ATTACK...")
    swarm_result = await honeypot_net.simulate_attack('swarm', 'high')
    print(f"  Targets Hit: {swarm_result['targets_hit']}")
    print(f"  Events Generated: {swarm_result['events_generated']}")

    await asyncio.sleep(2)  # Let monitoring detect it

    # Check alerts
    print("\n📊 Alert Analysis:")
    alerts_processed = 0
    while not honeypot_net.alerts.empty() and alerts_processed < 10:
        alert = await honeypot_net.alerts.get()
        if alert.get('type') == 'SWARM_DETECTED':
            print(f"  🚨 SWARM DETECTED!")
            print(f"     Affected Honeypots: {len(alert['affected_honeypots'])}")
        else:
            print(f"  Alert: {alert.get('threat_type', 'unknown')} from {alert.get('attacker_ip', 'unknown')}")
        alerts_processed += 1

    # Final statistics
    final_stats = honeypot_net.get_statistics()
    print(f"\nFinal Statistics:")
    print(f"  Total Events Captured: {final_stats['total_events']}")
    print(f"  Unique Attackers: {final_stats['unique_attackers']}")
    print(f"  Swarm Detections: {final_stats['swarm_detections']}")

    # Cancel monitoring task
    monitor_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())