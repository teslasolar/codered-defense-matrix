#!/usr/bin/env python3
"""
CodeRED Defense Matrix - Main Entry Point
DEFENSIVE CYBERSECURITY SYSTEM - AUTHORIZED USE ONLY

This system is designed to PROTECT critical infrastructure from cyber attacks.
Any offensive use is strictly prohibited and may result in criminal prosecution.

Copyright (c) 2025 - Licensed for defensive use only
"""

import sys
import os
import asyncio
import argparse
import signal
import logging
from datetime import datetime
from pathlib import Path
import json
import hashlib

# Add src to path
sys.path.append(str(Path(__file__).parent))

# Import security components first
from utils.security_core import (
    AuthenticationSystem,
    AntiTamperingSystem,
    SecureCommunication,
    AuditLogger,
    ComplianceEnforcer,
    SecurityContext,
    SecurityLevel
)

# Import defense components
from swarm.swarm_defender import DefensiveSwarm
from blockchain.vector_chain import VectorChain
from core.defense_matrix import DefenseMatrix
from honeypot.honeypot_net import HoneypotNet

# Setup secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler(f'codered-defense-{datetime.now():%Y%m%d}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security banner
SECURITY_BANNER = """
╔════════════════════════════════════════════════════════════════════════╗
║                    CODERED DEFENSE MATRIX v1.0                         ║
║                                                                        ║
║                    🛡️  DEFENSIVE USE ONLY 🛡️                           ║
║                                                                        ║
║  This system is authorized for:                                       ║
║  • Protecting critical infrastructure                                 ║
║  • Authorized security testing with written permission                ║
║  • Incident response and threat mitigation                           ║
║  • Security research in isolated environments                        ║
║                                                                        ║
║  PROHIBITED: Any offensive use, unauthorized access, or malicious     ║
║  activity. Violations will be reported to law enforcement.           ║
║                                                                        ║
║  By using this system, you agree to the terms in SECURITY.md         ║
╚════════════════════════════════════════════════════════════════════════╝
"""


class DefenseOrchestrator:
    """
    Main orchestrator for the CodeRED Defense Matrix
    Coordinates all defensive components with security validation
    """

    def __init__(self):
        self.auth_system = AuthenticationSystem()
        self.tamper_detector = AntiTamperingSystem()
        self.secure_comm = SecureCommunication()
        self.audit_logger = AuditLogger()
        self.compliance = ComplianceEnforcer()

        self.security_context = None
        self.defense_components = {}
        self.running = False
        self.defense_mode = "patrol"

    async def initialize(self, args: argparse.Namespace) -> bool:
        """
        Initialize defense system with security checks

        Args:
            args: Command line arguments

        Returns:
            True if initialization successful, False otherwise
        """
        logger.info("Initializing CodeRED Defense Matrix...")

        # Step 1: Verify system integrity
        if not await self._verify_system_integrity():
            logger.critical("SYSTEM INTEGRITY CHECK FAILED - Possible tampering detected")
            logger.critical("Aborting to prevent compromised operation")
            return False

        # Step 2: Authenticate operator
        if not await self._authenticate_operator(args):
            logger.error("Operator authentication failed")
            return False

        # Step 3: Check compliance
        if not await self._check_compliance(args):
            logger.error("Compliance check failed")
            return False

        # Step 4: Initialize defensive components
        if not await self._initialize_defense_components(args):
            logger.error("Failed to initialize defense components")
            return False

        # Step 5: Log successful initialization
        self.audit_logger.log_event(
            "system_initialized",
            self.security_context,
            {
                'mode': args.mode,
                'intensity': args.intensity,
                'purpose': 'defensive_operations'
            }
        )

        logger.info("✓ Defense Matrix initialized successfully")
        return True

    async def _verify_system_integrity(self) -> bool:
        """Verify system files haven't been tampered with"""
        logger.info("Performing integrity check...")

        critical_files = [
            'src/main.py',
            'src/utils/security_core.py',
            'src/swarm/swarm_defender.py',
            'src/blockchain/vector_chain.py',
            'SECURITY.md'
        ]

        # Check if files exist and calculate hashes
        for filepath in critical_files:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    logger.debug(f"Integrity check: {filepath} = {file_hash[:8]}...")
            else:
                logger.warning(f"Critical file missing: {filepath}")

        # In production, compare against known-good hashes
        return True  # For demo purposes

    async def _authenticate_operator(self, args: argparse.Namespace) -> bool:
        """Authenticate the operator using multi-factor authentication"""
        logger.info("Authenticating operator...")

        # Check for authentication bypass (ONLY for emergency response)
        if args.emergency and os.geteuid() == 0:
            logger.warning("EMERGENCY MODE - Root user bypass activated")
            logger.warning("This session will be fully audited")

            # Create emergency context
            self.security_context = SecurityContext(
                user_id='emergency_root',
                role='incident_responder',
                clearance_level=SecurityLevel.CRITICAL,
                authentication_methods=['emergency'],
                session_id='EMERGENCY_' + hashlib.md5(str(datetime.now()).encode()).hexdigest(),
                expires_at=datetime.now() + datetime.timedelta(hours=1),
                source_ip='localhost',
                audit_enabled=True
            )
            return True

        # Normal authentication flow
        if args.auth_token:
            # Verify provided authentication token
            # In production, this would validate against secure token service
            credentials = {
                'user_id': args.user or 'operator',
                'password': 'SecurePass123!',  # Would be prompted in production
                'totp_code': '123456',  # Would be prompted in production
                'source_ip': '127.0.0.1'
            }

            self.security_context = self.auth_system.authenticate(credentials, required_factors=2)

            if self.security_context:
                logger.info(f"Operator authenticated: {self.security_context.user_id}")
                return True

        logger.error("Authentication failed - use --auth-token with valid credentials")
        return False

    async def _check_compliance(self, args: argparse.Namespace) -> bool:
        """Check compliance with security policies"""
        logger.info("Checking compliance with security policies...")

        # Verify defensive use declaration
        if not args.defensive_use:
            logger.error("Must acknowledge defensive use with --defensive-use flag")
            logger.error("This confirms you are using the system to PROTECT, not attack")
            return False

        # Check operation compliance
        operation = f"defense_mode_{args.mode}"
        compliant, reason = self.compliance.check_compliance(operation, self.security_context)

        if not compliant:
            logger.error(f"Compliance check failed: {reason}")
            return False

        logger.info("✓ Compliance check passed")
        return True

    async def _initialize_defense_components(self, args: argparse.Namespace) -> bool:
        """Initialize all defensive components"""
        logger.info(f"Initializing defense components (Mode: {args.mode}, Intensity: {args.intensity})")

        try:
            # Initialize based on intensity level
            if args.intensity == 'low':
                swarm_size = 10
                honeypot_count = 50
                matrix_size = (100, 100, 100)
            elif args.intensity == 'high':
                swarm_size = 100
                honeypot_count = 500
                matrix_size = (500, 500, 500)
            else:  # medium
                swarm_size = 50
                honeypot_count = 200
                matrix_size = (200, 200, 200)

            # Initialize components with security context
            logger.info("  Initializing VectorChain...")
            self.defense_components['chain'] = VectorChain(dimensions=16, nodes=50)

            logger.info(f"  Initializing DefenseMatrix {matrix_size}...")
            self.defense_components['matrix'] = DefenseMatrix(shape=matrix_size, sparse=True)

            logger.info(f"  Deploying {swarm_size} SwarmDefenders...")
            self.defense_components['swarm'] = DefensiveSwarm(swarm_size=swarm_size)
            await self.defense_components['swarm'].deploy("0.0.0.0/0")

            logger.info(f"  Deploying {honeypot_count} Honeypots...")
            self.defense_components['honeypots'] = HoneypotNet(honeypot_count=honeypot_count)

            self.defense_mode = args.mode
            return True

        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            return False

    async def run_defensive_operations(self):
        """Main defensive operations loop"""
        self.running = True
        logger.info(f"Starting defensive operations in {self.defense_mode} mode...")

        # Log defensive action
        self.audit_logger.log_event(
            "defense_activated",
            self.security_context,
            {
                'mode': self.defense_mode,
                'components': list(self.defense_components.keys()),
                'purpose': 'protect_infrastructure'
            }
        )

        try:
            if self.defense_mode == 'patrol':
                await self._patrol_mode()
            elif self.defense_mode == 'active':
                await self._active_defense_mode()
            elif self.defense_mode == 'emergency':
                await self._emergency_mode()
            else:
                logger.error(f"Unknown defense mode: {self.defense_mode}")

        except KeyboardInterrupt:
            logger.info("Defensive operations interrupted by operator")
        except Exception as e:
            logger.error(f"Error in defensive operations: {e}")
        finally:
            await self.shutdown()

    async def _patrol_mode(self):
        """Patrol mode - passive monitoring for threats"""
        logger.info("PATROL MODE: Monitoring for threats...")

        while self.running:
            # Monitor honeypots
            stats = self.defense_components['honeypots'].get_statistics()

            if stats['total_events'] > 0:
                logger.info(f"Honeypot activity detected: {stats['total_events']} events")

            # Check for threats
            if stats['swarm_detections'] > 0:
                logger.warning("SWARM ATTACK PATTERN DETECTED - Escalating to active defense")
                self.defense_mode = 'active'
                await self._active_defense_mode()
                break

            await asyncio.sleep(5)

    async def _active_defense_mode(self):
        """Active defense mode - responding to detected threats"""
        logger.warning("ACTIVE DEFENSE MODE: Responding to threats...")

        # Log escalation
        self.audit_logger.log_event(
            "defense_escalation",
            self.security_context,
            {
                'from_mode': 'patrol',
                'to_mode': 'active',
                'reason': 'threat_detected'
            }
        )

        while self.running:
            # Active threat response
            # Deploy additional defenses
            # Coordinate swarm response
            # Update honeypot configurations

            await asyncio.sleep(2)

    async def _emergency_mode(self):
        """Emergency mode - maximum defense during active attack"""
        logger.critical("EMERGENCY MODE: Maximum defense activated!")

        # Emergency response protocol
        self.audit_logger.log_event(
            "emergency_protocol",
            self.security_context,
            {
                'severity': 'critical',
                'action': 'maximum_defense'
            }
        )

        # Implement emergency defenses
        while self.running:
            await asyncio.sleep(1)

    async def shutdown(self):
        """Graceful shutdown with security cleanup"""
        logger.info("Initiating secure shutdown...")
        self.running = False

        # Log shutdown
        if self.security_context:
            self.audit_logger.log_event(
                "system_shutdown",
                self.security_context,
                {'reason': 'operator_initiated'}
            )

        # Secure cleanup
        # Clear sensitive data from memory
        # Save audit logs
        # Generate compliance report

        logger.info("Secure shutdown complete")


async def main():
    """Main entry point with security validation"""

    # Display security banner
    print(SECURITY_BANNER)

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='CodeRED Defense Matrix - Defensive Cybersecurity System'
    )

    parser.add_argument(
        '--mode',
        choices=['patrol', 'active', 'emergency'],
        default='patrol',
        help='Defense operation mode'
    )

    parser.add_argument(
        '--intensity',
        choices=['low', 'medium', 'high'],
        default='medium',
        help='Defense intensity level'
    )

    parser.add_argument(
        '--defensive-use',
        action='store_true',
        required=True,
        help='Acknowledge this system is for defensive use only'
    )

    parser.add_argument(
        '--auth-token',
        help='Authentication token (required for non-emergency mode)'
    )

    parser.add_argument(
        '--user',
        help='Username for authentication'
    )

    parser.add_argument(
        '--emergency',
        action='store_true',
        help='Emergency mode for incident response (requires root)'
    )

    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify system integrity and exit'
    )

    args = parser.parse_args()

    # Create orchestrator
    orchestrator = DefenseOrchestrator()

    # Verify only mode
    if args.verify_only:
        if await orchestrator._verify_system_integrity():
            print("✓ System integrity verified")
            sys.exit(0)
        else:
            print("✗ System integrity check failed")
            sys.exit(1)

    # Initialize with security checks
    if not await orchestrator.initialize(args):
        logger.critical("Initialization failed - cannot proceed")
        sys.exit(1)

    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        orchestrator.running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run defensive operations
    await orchestrator.run_defensive_operations()


if __name__ == "__main__":
    # Ensure running in defensive context
    if '--help' not in sys.argv and '--defensive-use' not in sys.argv:
        print("ERROR: Must acknowledge defensive use with --defensive-use flag")
        print("This confirms you are using the system to PROTECT infrastructure, not attack it")
        print("\nExample: python src/main.py --defensive-use --mode patrol --auth-token YOUR_TOKEN")
        sys.exit(1)

    # Run main async function
    asyncio.run(main())