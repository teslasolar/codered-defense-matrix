"""
VectorChain: Blockchain-based alert verification using vector embeddings
Prevents false alert injection through distributed consensus
"""

import hashlib
import json
import time
from typing import List, Dict, Any, Optional
import numpy as np
from dataclasses import dataclass, asdict
from datetime import datetime
import asyncio
from collections import deque


@dataclass
class Block:
    """Single block in the VectorChain"""
    index: int
    timestamp: float
    alert_data: Dict[str, Any]
    vector_hash: str
    previous_hash: str
    nonce: int = 0
    signatures: List[str] = None

    def __post_init__(self):
        if self.signatures is None:
            self.signatures = []

    def calculate_hash(self) -> str:
        """Calculate block hash"""
        block_string = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class VectorChain:
    """
    Distributed blockchain with vector consensus for alert verification.
    Uses 16-dimensional embeddings for similarity-based consensus.
    """

    def __init__(self, dimensions: int = 16, nodes: int = 100, consensus_threshold: float = 0.51):
        """
        Initialize VectorChain

        Args:
            dimensions: Vector embedding dimensions (default 16 for lightweight)
            nodes: Number of verification nodes
            consensus_threshold: Required consensus ratio (default 51%)
        """
        self.dimensions = dimensions
        self.nodes = nodes
        self.consensus_threshold = consensus_threshold

        # Blockchain storage
        self.chain: List[Block] = []
        self.pending_alerts: deque = deque(maxlen=1000)

        # Node vectors for consensus
        self.node_vectors = np.random.randn(nodes, dimensions) * 0.1
        self.node_vectors /= np.linalg.norm(self.node_vectors, axis=1, keepdims=True)

        # Performance metrics
        self.verified_count = 0
        self.rejected_count = 0
        self.avg_verification_time = 0

        # Create genesis block
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        """Create the first block in the chain"""
        genesis = Block(
            index=0,
            timestamp=time.time(),
            alert_data={"type": "genesis", "message": "CodeRED Defense Matrix Initialized"},
            vector_hash="0" * 64,
            previous_hash="0" * 64
        )
        self.chain.append(genesis)

    def embed_alert(self, alert_data: Dict[str, Any]) -> np.ndarray:
        """
        Convert alert data to vector embedding

        Args:
            alert_data: Alert information to embed

        Returns:
            16-dimensional vector representation
        """
        # Simple but effective: hash-based embedding
        alert_str = json.dumps(alert_data, sort_keys=True)
        hash_bytes = hashlib.sha256(alert_str.encode()).digest()

        # Convert to vector
        vector = np.frombuffer(hash_bytes[:self.dimensions], dtype=np.uint8)
        vector = vector.astype(np.float32) / 255.0  # Normalize

        # Add semantic features if available
        if 'severity' in alert_data:
            severity_map = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
            vector[0] = severity_map.get(alert_data['severity'], 0.5)

        if 'type' in alert_data:
            type_hash = hashlib.md5(alert_data['type'].encode()).digest()[0]
            vector[1] = type_hash / 255.0

        return vector / np.linalg.norm(vector)  # L2 normalize

    def cosine_similarity(self, v1: np.ndarray, v2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors"""
        return np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2) + 1e-8)

    async def verify_alert(self, alert_data: Dict[str, Any], signatures: List[str]) -> bool:
        """
        Verify alert through vector consensus

        Args:
            alert_data: Alert to verify
            signatures: Node signatures supporting the alert

        Returns:
            True if consensus reached, False otherwise
        """
        start_time = time.time()

        # Generate alert vector
        alert_vector = self.embed_alert(alert_data)

        # Check each signature's vector similarity
        valid_signatures = 0
        for sig in signatures:
            # Extract node ID from signature (simplified)
            node_id = hash(sig) % self.nodes

            # Calculate similarity between alert vector and node's verification vector
            node_vector = self.node_vectors[node_id]
            similarity = self.cosine_similarity(alert_vector, node_vector)

            # Node confirms if similarity is high enough
            if similarity > 0.7:  # Node-specific threshold
                valid_signatures += 1

        # Check consensus
        consensus_ratio = valid_signatures / len(signatures) if signatures else 0
        verified = consensus_ratio >= self.consensus_threshold

        # Update metrics
        verification_time = time.time() - start_time
        self.avg_verification_time = (self.avg_verification_time * self.verified_count + verification_time) / (self.verified_count + 1)

        if verified:
            self.verified_count += 1
            await self.add_block(alert_data, signatures)
        else:
            self.rejected_count += 1

        return verified

    async def add_block(self, alert_data: Dict[str, Any], signatures: List[str]) -> Block:
        """
        Add verified alert to blockchain

        Args:
            alert_data: Verified alert data
            signatures: Supporting signatures

        Returns:
            New block added to chain
        """
        # Create vector hash
        alert_vector = self.embed_alert(alert_data)
        vector_hash = hashlib.sha256(alert_vector.tobytes()).hexdigest()

        # Create new block
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            alert_data=alert_data,
            vector_hash=vector_hash,
            previous_hash=self.chain[-1].calculate_hash() if self.chain else "0" * 64,
            signatures=signatures
        )

        # Mine block (simplified proof of work)
        new_block = self._mine_block(new_block)

        # Add to chain
        self.chain.append(new_block)

        return new_block

    def _mine_block(self, block: Block, difficulty: int = 2) -> Block:
        """
        Simple proof of work mining

        Args:
            block: Block to mine
            difficulty: Number of leading zeros required

        Returns:
            Mined block with valid nonce
        """
        target = "0" * difficulty

        while not block.calculate_hash().startswith(target):
            block.nonce += 1

        return block

    def validate_chain(self) -> bool:
        """
        Validate entire blockchain integrity

        Returns:
            True if chain is valid, False otherwise
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check hash linkage
            if current_block.previous_hash != previous_block.calculate_hash():
                return False

            # Verify proof of work
            if not current_block.calculate_hash().startswith("00"):  # Assuming difficulty 2
                return False

        return True

    async def broadcast_verified_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Broadcast alert after verification

        Args:
            alert_data: Alert to broadcast

        Returns:
            Broadcast result with metadata
        """
        # Check if alert is in the chain (verified)
        for block in reversed(self.chain):
            if block.alert_data == alert_data:
                return {
                    'status': 'broadcast',
                    'block_index': block.index,
                    'timestamp': block.timestamp,
                    'vector_hash': block.vector_hash,
                    'signatures': len(block.signatures),
                    'alert': alert_data
                }

        return {'status': 'not_verified', 'alert': alert_data}

    def get_chain_status(self) -> Dict[str, Any]:
        """Get current blockchain status"""
        return {
            'chain_length': len(self.chain),
            'verified_alerts': self.verified_count,
            'rejected_alerts': self.rejected_count,
            'avg_verification_time_ms': self.avg_verification_time * 1000,
            'consensus_threshold': self.consensus_threshold,
            'total_nodes': self.nodes,
            'vector_dimensions': self.dimensions,
            'chain_valid': self.validate_chain()
        }

    async def simulate_node_signatures(self, alert_data: Dict[str, Any], support_ratio: float = 0.7) -> List[str]:
        """
        Simulate node signatures for testing

        Args:
            alert_data: Alert to sign
            support_ratio: Fraction of nodes supporting the alert

        Returns:
            List of simulated signatures
        """
        num_signatures = int(self.nodes * support_ratio)
        signatures = []

        for i in range(num_signatures):
            # Simulate signature (in production, use real cryptographic signatures)
            sig_data = f"{i}:{json.dumps(alert_data)}:{time.time()}"
            signature = hashlib.sha256(sig_data.encode()).hexdigest()
            signatures.append(signature)

        return signatures


class VectorConsensus:
    """
    Distributed consensus mechanism using vector similarity
    """

    def __init__(self, chain: VectorChain):
        self.chain = chain
        self.voting_nodes: Dict[int, np.ndarray] = {}

    async def request_consensus(self, alert_data: Dict[str, Any], timeout: float = 5.0) -> bool:
        """
        Request consensus from network nodes

        Args:
            alert_data: Alert requiring consensus
            timeout: Maximum time to wait for consensus

        Returns:
            True if consensus reached within timeout
        """
        start_time = time.time()
        required_votes = int(self.chain.nodes * self.chain.consensus_threshold)
        votes_received = 0

        # Broadcast to all nodes (simulated)
        alert_vector = self.chain.embed_alert(alert_data)

        while time.time() - start_time < timeout and votes_received < required_votes:
            # Simulate node responses
            for node_id in range(self.chain.nodes):
                if node_id not in self.voting_nodes:
                    # Node evaluates alert
                    node_vector = self.chain.node_vectors[node_id]
                    similarity = self.chain.cosine_similarity(alert_vector, node_vector)

                    if similarity > 0.6:  # Node approves
                        self.voting_nodes[node_id] = node_vector
                        votes_received += 1

                        if votes_received >= required_votes:
                            return True

            await asyncio.sleep(0.1)  # Small delay between checks

        return False


# Example usage and testing
async def main():
    """Demonstration of VectorChain capabilities"""
    print("Initializing CodeRED VectorChain Defense System...")

    # Create chain
    chain = VectorChain(dimensions=16, nodes=100, consensus_threshold=0.51)
    consensus = VectorConsensus(chain)

    # Test alert
    test_alert = {
        'type': 'emergency',
        'severity': 'critical',
        'location': 'St. Louis Power Grid',
        'threat': 'AI Swarm Attack Detected',
        'timestamp': datetime.now().isoformat(),
        'affected_systems': 1247,
        'response': 'automatic_isolation'
    }

    print(f"\nTesting alert verification: {test_alert['threat']}")

    # Simulate node signatures (70% support)
    signatures = await chain.simulate_node_signatures(test_alert, support_ratio=0.7)

    # Verify alert
    verified = await chain.verify_alert(test_alert, signatures)

    if verified:
        print(f"✓ Alert VERIFIED and added to blockchain")
        result = await chain.broadcast_verified_alert(test_alert)
        print(f"  Block Index: {result.get('block_index')}")
        print(f"  Signatures: {result.get('signatures')}")
    else:
        print(f"✗ Alert REJECTED - insufficient consensus")

    # Show chain status
    status = chain.get_chain_status()
    print(f"\nBlockchain Status:")
    print(f"  Chain Length: {status['chain_length']}")
    print(f"  Verified Alerts: {status['verified_alerts']}")
    print(f"  Rejected Alerts: {status['rejected_alerts']}")
    print(f"  Avg Verification Time: {status['avg_verification_time_ms']:.2f}ms")
    print(f"  Chain Valid: {status['chain_valid']}")


if __name__ == "__main__":
    asyncio.run(main())