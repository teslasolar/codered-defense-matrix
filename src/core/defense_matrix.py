"""
DefenseMatrix: 3D spatial defense grid system (1000x1000x1000)
Provides distributed defense positioning and resource allocation
"""

import asyncio
import numpy as np
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import hashlib
import time
from collections import defaultdict, deque
import heapq


class ZoneStatus(Enum):
    """Defense zone status levels"""
    SECURE = "secure"           # No threats
    MONITORING = "monitoring"   # Elevated monitoring
    CONTESTED = "contested"     # Active threats
    COMPROMISED = "compromised" # Zone breached
    ISOLATED = "isolated"       # Quarantined


@dataclass
class DefenseNode:
    """Single defense node in the matrix"""
    position: Tuple[int, int, int]
    node_id: str
    status: ZoneStatus
    defender_count: int
    threat_score: float
    last_update: float
    connections: Set[str]


@dataclass
class ThreatVector:
    """3D threat vector for spatial analysis"""
    origin: Tuple[int, int, int]
    direction: np.ndarray
    magnitude: float
    threat_type: str
    timestamp: float


class DefenseMatrix:
    """
    3D Defense Grid System
    Manages spatial defense positioning and threat response
    """

    def __init__(self, shape: Tuple[int, int, int] = (1000, 1000, 1000),
                 sparse: bool = True):
        """
        Initialize DefenseMatrix

        Args:
            shape: 3D grid dimensions (default 1000³)
            sparse: Use sparse storage for efficiency
        """
        self.shape = shape
        self.sparse = sparse

        # Grid storage (sparse for efficiency)
        if sparse:
            self.grid = {}  # Dict for sparse storage
        else:
            # Warning: 1000³ = 1 billion cells! Use sparse for production
            self.grid = np.zeros(shape, dtype=np.uint8)

        # Defense nodes by position
        self.nodes: Dict[Tuple[int, int, int], DefenseNode] = {}

        # Active swarms by zone
        self.active_swarms: Dict[str, List] = defaultdict(list)

        # Threat tracking
        self.threat_map: Dict[Tuple[int, int, int], float] = {}
        self.threat_vectors: deque = deque(maxlen=1000)

        # Zone management
        self.zones = self._initialize_zones()
        self.critical_zones: Set[Tuple[int, int, int]] = set()

        # Performance metrics
        self.response_times: deque = deque(maxlen=100)
        self.threat_mitigation_rate = 0.0

    def _initialize_zones(self) -> Dict[str, Dict]:
        """Initialize defense zones"""
        zones = {}

        # Divide grid into sectors (10x10x10 = 1000 sectors)
        sector_size = (self.shape[0] // 10, self.shape[1] // 10, self.shape[2] // 10)

        for x in range(10):
            for y in range(10):
                for z in range(10):
                    zone_id = f"sector_{x}{y}{z}"
                    zones[zone_id] = {
                        'bounds': (
                            (x * sector_size[0], (x + 1) * sector_size[0]),
                            (y * sector_size[1], (y + 1) * sector_size[1]),
                            (z * sector_size[2], (z + 1) * sector_size[2])
                        ),
                        'status': ZoneStatus.SECURE,
                        'defender_count': 0,
                        'threat_level': 0.0
                    }

        return zones

    def coord_to_zone(self, coord: Tuple[int, int, int]) -> str:
        """Convert coordinate to zone ID"""
        sector_size = (self.shape[0] // 10, self.shape[1] // 10, self.shape[2] // 10)
        x = min(coord[0] // sector_size[0], 9)
        y = min(coord[1] // sector_size[1], 9)
        z = min(coord[2] // sector_size[2], 9)
        return f"sector_{x}{y}{z}"

    async def deploy_swarm(self, position: Tuple[int, int, int],
                          swarm_size: int = 100) -> Dict[str, Any]:
        """
        Deploy defensive swarm at position

        Args:
            position: 3D coordinate for deployment
            swarm_size: Number of defenders to deploy

        Returns:
            Deployment result
        """
        x, y, z = position

        # Validate position
        if not self._validate_position(position):
            return {'status': 'error', 'message': 'Invalid position'}

        # Create or update node
        node_id = f"node_{x}_{y}_{z}"
        node = DefenseNode(
            position=position,
            node_id=node_id,
            status=ZoneStatus.MONITORING,
            defender_count=swarm_size,
            threat_score=0.0,
            last_update=time.time(),
            connections=set()
        )

        self.nodes[position] = node

        # Update grid
        if self.sparse:
            self.grid[position] = swarm_size
        else:
            self.grid[x, y, z] = min(swarm_size, 255)  # Cap at 255 for uint8

        # Add to active swarms
        zone_id = self.coord_to_zone(position)
        self.active_swarms[zone_id].append({
            'position': position,
            'size': swarm_size,
            'deployed_time': time.time()
        })

        # Update zone status
        self.zones[zone_id]['defender_count'] += swarm_size

        # Establish connections to nearby nodes
        await self._establish_connections(node)

        return {
            'status': 'deployed',
            'node_id': node_id,
            'position': position,
            'swarm_size': swarm_size,
            'zone': zone_id,
            'connections': len(node.connections)
        }

    async def _establish_connections(self, node: DefenseNode, radius: int = 50) -> None:
        """Establish connections to nearby nodes"""
        x, y, z = node.position

        for dx in range(-radius, radius + 1, 10):
            for dy in range(-radius, radius + 1, 10):
                for dz in range(-radius, radius + 1, 10):
                    if dx == 0 and dy == 0 and dz == 0:
                        continue

                    neighbor_pos = (x + dx, y + dy, z + dz)

                    if neighbor_pos in self.nodes:
                        neighbor = self.nodes[neighbor_pos]
                        node.connections.add(neighbor.node_id)
                        neighbor.connections.add(node.node_id)

    def _validate_position(self, position: Tuple[int, int, int]) -> bool:
        """Validate position is within grid bounds"""
        x, y, z = position
        return (0 <= x < self.shape[0] and
                0 <= y < self.shape[1] and
                0 <= z < self.shape[2])

    async def respond_to_attack(self, attack_vector: ThreatVector) -> Dict[str, Any]:
        """
        Respond to detected attack vector

        Args:
            attack_vector: 3D threat vector

        Returns:
            Response result
        """
        start_time = time.time()

        # Store threat vector
        self.threat_vectors.append(attack_vector)

        # Find nearest defenders
        defenders = await self._find_nearest_defenders(attack_vector.origin, radius=100)

        if not defenders:
            return {
                'status': 'no_defenders',
                'threat_origin': attack_vector.origin,
                'recommendation': 'deploy_emergency_swarm'
            }

        # Calculate interception points
        interception_points = self._calculate_interception(attack_vector, defenders)

        # Deploy defenders to interception points
        responses = []
        for point in interception_points[:10]:  # Deploy up to 10 groups
            response = await self._deploy_interceptors(point, attack_vector)
            responses.append(response)

        # Update threat map
        self._update_threat_map(attack_vector)

        # Calculate response time
        response_time = time.time() - start_time
        self.response_times.append(response_time)

        return {
            'status': 'responding',
            'threat_vector': {
                'origin': attack_vector.origin,
                'direction': attack_vector.direction.tolist(),
                'magnitude': attack_vector.magnitude,
                'type': attack_vector.threat_type
            },
            'defenders_activated': len(defenders),
            'interception_points': len(interception_points),
            'response_time_ms': response_time * 1000,
            'responses': responses[:5]  # First 5 responses
        }

    async def _find_nearest_defenders(self, position: Tuple[int, int, int],
                                     radius: int = 100) -> List[DefenseNode]:
        """Find defenders within radius of position"""
        defenders = []
        x, y, z = position

        # Efficient search using zone system
        zone_id = self.coord_to_zone(position)
        nearby_zones = self._get_nearby_zones(zone_id)

        for zone in nearby_zones:
            for swarm in self.active_swarms.get(zone, []):
                swarm_pos = swarm['position']
                distance = np.linalg.norm(np.array(swarm_pos) - np.array(position))

                if distance <= radius:
                    if swarm_pos in self.nodes:
                        defenders.append(self.nodes[swarm_pos])

        return sorted(defenders, key=lambda d: np.linalg.norm(
            np.array(d.position) - np.array(position)))

    def _get_nearby_zones(self, zone_id: str) -> List[str]:
        """Get zones adjacent to given zone"""
        # Extract sector coordinates
        parts = zone_id.split('_')
        if len(parts) != 2:
            return [zone_id]

        sector_str = parts[1]
        x, y, z = int(sector_str[0]), int(sector_str[1]), int(sector_str[2])

        nearby = []
        for dx in [-1, 0, 1]:
            for dy in [-1, 0, 1]:
                for dz in [-1, 0, 1]:
                    nx, ny, nz = x + dx, y + dy, z + dz
                    if 0 <= nx < 10 and 0 <= ny < 10 and 0 <= nz < 10:
                        nearby.append(f"sector_{nx}{ny}{nz}")

        return nearby

    def _calculate_interception(self, threat: ThreatVector,
                               defenders: List[DefenseNode]) -> List[Tuple[int, int, int]]:
        """Calculate optimal interception points"""
        interception_points = []

        # Project threat path
        threat_path = []
        current = np.array(threat.origin, dtype=float)

        for step in range(int(threat.magnitude)):
            current = current + threat.direction
            grid_pos = tuple(current.astype(int))

            if self._validate_position(grid_pos):
                threat_path.append(grid_pos)

        # Find interception points along path
        for i in range(0, len(threat_path), max(1, len(threat_path) // 10)):
            point = threat_path[i]

            # Check if defenders can reach this point
            for defender in defenders:
                defender_pos = np.array(defender.position)
                intercept_pos = np.array(point)
                distance = np.linalg.norm(intercept_pos - defender_pos)

                # Simple time-to-intercept calculation
                if distance < threat.magnitude - i:
                    interception_points.append(point)
                    break

        return interception_points

    async def _deploy_interceptors(self, position: Tuple[int, int, int],
                                  threat: ThreatVector) -> Dict[str, Any]:
        """Deploy interceptors to specific position"""
        # Simulate interceptor deployment
        return {
            'position': position,
            'interceptors': 10,
            'eta_seconds': np.linalg.norm(np.array(position) - threat.origin) / 50,  # 50 units/sec
            'strategy': 'containment'
        }

    def _update_threat_map(self, threat: ThreatVector) -> None:
        """Update threat heat map"""
        # Mark threat origin
        self.threat_map[threat.origin] = threat.magnitude

        # Spread threat influence
        origin = np.array(threat.origin)
        spread_radius = int(threat.magnitude * 0.1)

        for dx in range(-spread_radius, spread_radius + 1):
            for dy in range(-spread_radius, spread_radius + 1):
                for dz in range(-spread_radius, spread_radius + 1):
                    pos = tuple((origin + [dx, dy, dz]).astype(int))

                    if self._validate_position(pos):
                        distance = np.sqrt(dx*dx + dy*dy + dz*dz)
                        influence = threat.magnitude / (distance + 1)
                        self.threat_map[pos] = self.threat_map.get(pos, 0) + influence

    async def isolate_zone(self, zone_id: str) -> Dict[str, Any]:
        """
        Isolate compromised zone

        Args:
            zone_id: Zone to isolate

        Returns:
            Isolation result
        """
        if zone_id not in self.zones:
            return {'status': 'error', 'message': 'Invalid zone'}

        zone = self.zones[zone_id]
        zone['status'] = ZoneStatus.ISOLATED

        # Cut connections from zone
        isolated_nodes = []
        for position, node in self.nodes.items():
            if self.coord_to_zone(position) == zone_id:
                # Clear connections
                for conn_id in node.connections:
                    # Remove reverse connections
                    for other_node in self.nodes.values():
                        if other_node.node_id == conn_id:
                            other_node.connections.discard(node.node_id)

                node.connections.clear()
                node.status = ZoneStatus.ISOLATED
                isolated_nodes.append(node.node_id)

        return {
            'status': 'isolated',
            'zone_id': zone_id,
            'isolated_nodes': len(isolated_nodes),
            'timestamp': time.time()
        }

    def get_matrix_status(self) -> Dict[str, Any]:
        """Get current defense matrix status"""
        total_defenders = sum(zone['defender_count'] for zone in self.zones.values())
        active_zones = sum(1 for zone in self.zones.values()
                          if zone['status'] != ZoneStatus.SECURE)
        compromised_zones = sum(1 for zone in self.zones.values()
                               if zone['status'] == ZoneStatus.COMPROMISED)

        # Calculate threat level
        if self.threat_map:
            avg_threat = np.mean(list(self.threat_map.values()))
            max_threat = max(self.threat_map.values())
        else:
            avg_threat = max_threat = 0

        # Calculate response metrics
        avg_response_time = np.mean(self.response_times) if self.response_times else 0

        return {
            'grid_dimensions': self.shape,
            'total_nodes': len(self.nodes),
            'total_defenders': total_defenders,
            'active_zones': active_zones,
            'compromised_zones': compromised_zones,
            'isolated_zones': sum(1 for z in self.zones.values()
                                 if z['status'] == ZoneStatus.ISOLATED),
            'threat_vectors_tracked': len(self.threat_vectors),
            'average_threat_level': avg_threat,
            'maximum_threat_level': max_threat,
            'average_response_time_ms': avg_response_time * 1000,
            'zones': {
                'total': len(self.zones),
                'secure': sum(1 for z in self.zones.values()
                             if z['status'] == ZoneStatus.SECURE),
                'monitoring': sum(1 for z in self.zones.values()
                                 if z['status'] == ZoneStatus.MONITORING),
                'contested': sum(1 for z in self.zones.values()
                                if z['status'] == ZoneStatus.CONTESTED)
            }
        }

    async def optimize_deployment(self) -> Dict[str, Any]:
        """
        Optimize defender deployment based on threat patterns

        Returns:
            Optimization recommendations
        """
        recommendations = []

        # Analyze threat concentration
        if self.threat_map:
            # Find hot spots
            hot_spots = sorted(self.threat_map.items(),
                             key=lambda x: x[1], reverse=True)[:10]

            for position, threat_level in hot_spots:
                # Check defender coverage
                defenders = await self._find_nearest_defenders(position, radius=50)

                if len(defenders) < 3:
                    recommendations.append({
                        'action': 'deploy',
                        'position': position,
                        'reason': f'High threat ({threat_level:.2f}), low coverage',
                        'priority': 'high'
                    })

        # Check isolated zones
        for zone_id, zone in self.zones.items():
            if zone['status'] == ZoneStatus.ISOLATED and zone['threat_level'] < 0.1:
                recommendations.append({
                    'action': 'reconnect',
                    'zone': zone_id,
                    'reason': 'Zone isolated but threat mitigated',
                    'priority': 'medium'
                })

        # Balance defender distribution
        zone_defenders = [(z, d['defender_count']) for z, d in self.zones.items()]
        avg_defenders = np.mean([d for _, d in zone_defenders]) if zone_defenders else 0

        for zone_id, count in zone_defenders:
            if count < avg_defenders * 0.5:
                recommendations.append({
                    'action': 'reinforce',
                    'zone': zone_id,
                    'reason': f'Under-defended ({count} vs {avg_defenders:.0f} avg)',
                    'priority': 'low'
                })

        return {
            'recommendations': recommendations[:20],  # Top 20 recommendations
            'optimization_metrics': {
                'coverage_ratio': len(self.nodes) / 1000,  # Nodes per 1000 cubic units
                'response_efficiency': 1.0 - (np.mean(self.response_times) if self.response_times else 0),
                'threat_mitigation_rate': self.threat_mitigation_rate
            }
        }


# Example usage
async def main():
    """Demonstration of DefenseMatrix capabilities"""
    print("Initializing CodeRED DefenseMatrix...")

    # Create matrix (smaller for demo)
    matrix = DefenseMatrix(shape=(100, 100, 100), sparse=True)

    # Deploy defensive swarms at strategic positions
    print("\nDeploying defensive swarms...")

    positions = [
        (50, 50, 50),   # Center
        (25, 25, 25),   # Quadrant 1
        (75, 75, 75),   # Quadrant 2
        (25, 75, 25),   # Quadrant 3
        (75, 25, 75),   # Quadrant 4
    ]

    for pos in positions:
        result = await matrix.deploy_swarm(pos, swarm_size=50)
        print(f"  Deployed at {pos}: {result['swarm_size']} defenders")

    # Simulate incoming threat
    print("\n⚠️  Simulating multi-vector attack...")

    threat = ThreatVector(
        origin=(10, 10, 10),
        direction=np.array([1, 1, 1]) / np.sqrt(3),  # Diagonal attack
        magnitude=100,
        threat_type='swarm',
        timestamp=time.time()
    )

    response = await matrix.respond_to_attack(threat)

    print(f"\n🛡️  Defense Response:")
    print(f"  Defenders Activated: {response['defenders_activated']}")
    print(f"  Interception Points: {response['interception_points']}")
    print(f"  Response Time: {response['response_time_ms']:.2f}ms")

    # Check matrix status
    status = matrix.get_matrix_status()
    print(f"\nMatrix Status:")
    print(f"  Total Nodes: {status['total_nodes']}")
    print(f"  Total Defenders: {status['total_defenders']}")
    print(f"  Active Zones: {status['active_zones']}")
    print(f"  Avg Response Time: {status['average_response_time_ms']:.2f}ms")

    # Get optimization recommendations
    optimization = await matrix.optimize_deployment()
    print(f"\nOptimization Recommendations:")
    for rec in optimization['recommendations'][:3]:
        print(f"  - {rec['action']}: {rec['reason']} (Priority: {rec['priority']})")


if __name__ == "__main__":
    asyncio.run(main())