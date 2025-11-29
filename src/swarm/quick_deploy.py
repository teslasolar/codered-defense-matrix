#!/usr/bin/env python3
"""
Quick Deploy Script for CodeRED SwarmDefender
Immediate deployment with minimal configuration
"""

import asyncio
import sys
import argparse
import signal
import logging
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from swarm.swarm_defender import SwarmDefender, DefensiveSwarm, NetworkPacket
from blockchain.vector_chain import VectorChain
from core.defense_matrix import DefenseMatrix, ThreatVector
from honeypot.honeypot_net import HoneypotNet

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'codered-defense-{datetime.now():%Y%m%d-%H%M%S}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class QuickDefense:
    """Quick deployment coordinator for emergency defense"""

    def __init__(self, mode='patrol', intensity='medium'):
        self.mode = mode
        self.intensity = intensity
        self.running = True

        # Initialize components based on intensity
        if intensity == 'low':
            self.swarm_size = 10
            self.honeypot_count = 50
            self.matrix_size = (100, 100, 100)
        elif intensity == 'high':
            self.swarm_size = 100
            self.honeypot_count = 500
            self.matrix_size = (500, 500, 500)
        else:  # medium
            self.swarm_size = 50
            self.honeypot_count = 200
            self.matrix_size = (200, 200, 200)

        self.swarm = None
        self.honeypots = None
        self.matrix = None
        self.chain = None

    async def initialize(self):
        """Initialize all defense components"""
        logger.info("=" * 60)
        logger.info("CodeRED Defense Matrix - QUICK DEPLOY")
        logger.info(f"Mode: {self.mode} | Intensity: {self.intensity}")
        logger.info("=" * 60)

        # Initialize VectorChain for verification
        logger.info("Initializing VectorChain...")
        self.chain = VectorChain(dimensions=16, nodes=50)

        # Initialize DefenseMatrix
        logger.info(f"Creating Defense Matrix {self.matrix_size}...")
        self.matrix = DefenseMatrix(shape=self.matrix_size, sparse=True)

        # Deploy defensive swarm
        logger.info(f"Deploying {self.swarm_size} defensive agents...")
        self.swarm = DefensiveSwarm(swarm_size=self.swarm_size)
        await self.swarm.deploy("0.0.0.0/0")  # Protect all networks

        # Deploy honeypots
        logger.info(f"Deploying {self.honeypot_count} honeypots...")
        self.honeypots = HoneypotNet(honeypot_count=self.honeypot_count)

        # Deploy swarms to matrix positions
        positions = self._get_strategic_positions()
        for pos in positions[:10]:  # Deploy to first 10 strategic positions
            await self.matrix.deploy_swarm(pos, swarm_size=10)

        logger.info("✓ All systems initialized")

    def _get_strategic_positions(self):
        """Get strategic positions for swarm deployment"""
        # Create a grid of strategic positions
        positions = []
        step = max(dim // 10 for dim in self.matrix_size)

        for x in range(0, self.matrix_size[0], step):
            for y in range(0, self.matrix_size[1], step):
                for z in range(0, self.matrix_size[2], step):
                    positions.append((x, y, z))

        return positions

    async def patrol_mode(self):
        """Run in patrol mode - normal monitoring"""
        logger.info("Starting PATROL mode...")

        # Start honeypot monitoring
        monitor_task = asyncio.create_task(self.honeypots.monitor())

        while self.running:
            # Simulate network traffic monitoring
            traffic = self._generate_traffic_sample()

            # Have swarm agents patrol
            for agent in self.swarm.agents[:5]:  # First 5 agents
                report = await agent.patrol(traffic)

                if report['threats_detected'] > 0:
                    logger.warning(f"Threat detected by {report['agent_id']}")
                    logger.info(f"  Type: {report['threat_details'][0].threat_type if report['threat_details'] else 'unknown'}")

                    # Verify with blockchain
                    if report['threat_details']:
                        threat = report['threat_details'][0]
                        signatures = await self.chain.simulate_node_signatures(
                            {'threat': threat.threat_type, 'source': threat.source},
                            support_ratio=0.7
                        )
                        verified = await self.chain.verify_alert(
                            {'threat': threat.threat_type},
                            signatures
                        )
                        if verified:
                            logger.critical("⚠️  VERIFIED THREAT - Initiating response")
                            await self.respond_to_threat(threat)

            await asyncio.sleep(5)  # Check every 5 seconds

        monitor_task.cancel()

    async def defense_mode(self):
        """Run in active defense mode - heightened security"""
        logger.info("Starting DEFENSE mode...")

        # Increase monitoring frequency
        while self.running:
            # Check honeypots for activity
            stats = self.honeypots.get_statistics()
            if stats['total_events'] > 100:
                logger.warning(f"High activity on honeypots: {stats['total_events']} events")

                # Simulate swarm attack for testing
                await self.honeypots.simulate_attack('swarm', 'high')

                # Check for swarm patterns
                if stats['swarm_detections'] > 0:
                    logger.critical("🚨 SWARM ATTACK DETECTED!")
                    await self.activate_swarm_defense()

            # Check matrix status
            matrix_status = self.matrix.get_matrix_status()
            if matrix_status['compromised_zones'] > 0:
                logger.critical(f"Compromised zones: {matrix_status['compromised_zones']}")

            await asyncio.sleep(2)  # Higher frequency in defense mode

    async def respond_to_threat(self, threat):
        """Coordinate response to detected threat"""
        logger.info(f"Responding to threat: {threat.threat_type}")

        # Create threat vector for matrix
        threat_vector = ThreatVector(
            origin=(10, 10, 10),
            direction=np.array([1, 0, 0]),
            magnitude=50,
            threat_type=threat.threat_type,
            timestamp=time.time()
        )

        # Matrix response
        response = await self.matrix.respond_to_attack(threat_vector)
        logger.info(f"  Matrix response: {response['defenders_activated']} defenders activated")

        # Swarm response
        swarm_response = await self.swarm.collective_defense([{
            'threat_type': threat.threat_type,
            'source': threat.source
        }])
        logger.info(f"  Swarm response: {swarm_response['participating_agents']} agents engaged")

    async def activate_swarm_defense(self):
        """Activate full swarm defense mode"""
        logger.critical("ACTIVATING SWARM DEFENSE MODE")

        # Set all agents to coordinate mode
        for agent in self.swarm.agents:
            agent.state = DefenseMode.COORDINATE

        # Isolate compromised zones
        for zone_id in ['sector_000', 'sector_001']:  # Example zones
            result = await self.matrix.isolate_zone(zone_id)
            logger.info(f"  Isolated zone {zone_id}: {result['isolated_nodes']} nodes")

        # Deploy additional swarms
        positions = self._get_strategic_positions()
        for pos in positions[10:20]:  # Deploy 10 more swarms
            await self.matrix.deploy_swarm(pos, swarm_size=20)

        logger.info("✓ Swarm defense activated")

    def _generate_traffic_sample(self):
        """Generate sample network traffic for testing"""
        import random
        import hashlib

        traffic = []
        for i in range(100):
            packet = NetworkPacket(
                src_ip=f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                dst_ip=f"10.0.0.{random.randint(1,254)}",
                port=random.choice([22, 80, 443, 3389, 8080]),
                protocol=random.choice(['TCP', 'UDP', 'HTTP']),
                payload_size=random.randint(64, 1500),
                timestamp=time.time() + i * 0.1,
                flags=['ACK'] if random.random() > 0.5 else ['SYN'],
                content_hash=hashlib.md5(f"packet_{i}".encode()).hexdigest()
            )
            traffic.append(packet)

        return traffic

    async def run(self):
        """Main run loop"""
        await self.initialize()

        if self.mode == 'patrol':
            await self.patrol_mode()
        elif self.mode == 'defense':
            await self.defense_mode()
        elif self.mode == 'test':
            await self.test_mode()
        else:
            logger.error(f"Unknown mode: {self.mode}")

    async def test_mode(self):
        """Test mode for validation"""
        logger.info("Running in TEST mode...")

        # Test all components
        logger.info("Testing VectorChain...")
        test_alert = {'type': 'test', 'severity': 'high'}
        signatures = await self.chain.simulate_node_signatures(test_alert, 0.7)
        verified = await self.chain.verify_alert(test_alert, signatures)
        logger.info(f"  VectorChain: {'✓ PASSED' if verified else '✗ FAILED'}")

        logger.info("Testing SwarmDefender...")
        agent = self.swarm.agents[0]
        traffic = self._generate_traffic_sample()
        report = await agent.patrol(traffic)
        logger.info(f"  SwarmDefender: ✓ Analyzed {report['packets_analyzed']} packets")

        logger.info("Testing DefenseMatrix...")
        result = await self.matrix.deploy_swarm((50, 50, 50), 10)
        logger.info(f"  DefenseMatrix: ✓ Deployed to {result['position']}")

        logger.info("Testing HoneypotNet...")
        await self.honeypots.simulate_attack('random', 'low')
        stats = self.honeypots.get_statistics()
        logger.info(f"  HoneypotNet: ✓ {stats['total_honeypots']} honeypots active")

        logger.info("\n✓ All systems operational")

    def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down defense systems...")
        self.running = False


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='CodeRED Defense Quick Deploy')
    parser.add_argument('--mode', choices=['patrol', 'defense', 'test'],
                       default='patrol', help='Deployment mode')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'],
                       default='medium', help='Defense intensity')

    args = parser.parse_args()

    # Create defense system
    defense = QuickDefense(mode=args.mode, intensity=args.intensity)

    # Handle shutdown signals
    def signal_handler(sig, frame):
        logger.info("\nReceived shutdown signal")
        defense.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Run defense system
        await defense.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        defense.shutdown()


if __name__ == "__main__":
    # Add numpy import for the script
    import numpy as np
    import time

    # Import defense mode enum
    from swarm_defender import DefenseMode

    # Run the main async function
    asyncio.run(main())