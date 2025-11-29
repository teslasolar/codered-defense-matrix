"""
Unit tests for VectorChain blockchain verification system
Tests alert verification, consensus, and blockchain integrity
"""

import pytest
import asyncio
import numpy as np
import json
import time
from unittest.mock import Mock, patch

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.blockchain.vector_chain import VectorChain, VectorConsensus, Block


class TestVectorChain:
    """Test blockchain-based alert verification"""

    def setup_method(self):
        """Setup test fixtures"""
        self.chain = VectorChain(dimensions=16, nodes=100, consensus_threshold=0.51)

    def test_genesis_block_creation(self):
        """Test that genesis block is created correctly"""
        assert len(self.chain.chain) == 1
        genesis = self.chain.chain[0]

        assert genesis.index == 0
        assert genesis.alert_data['type'] == 'genesis'
        assert genesis.previous_hash == "0" * 64

    def test_alert_embedding(self):
        """Test conversion of alert to vector embedding"""
        alert = {
            'type': 'emergency',
            'severity': 'critical',
            'location': 'power_grid_sector_7'
        }

        vector = self.chain.embed_alert(alert)

        assert vector.shape == (16,)  # 16-dimensional
        assert np.linalg.norm(vector) > 0  # Non-zero
        assert np.allclose(np.linalg.norm(vector), 1.0)  # Normalized

    def test_cosine_similarity(self):
        """Test cosine similarity calculation"""
        v1 = np.array([1, 0, 0])
        v2 = np.array([1, 0, 0])
        v3 = np.array([0, 1, 0])

        # Same vectors should have similarity ~1
        assert np.isclose(self.chain.cosine_similarity(v1, v2), 1.0)

        # Orthogonal vectors should have similarity ~0
        assert np.isclose(self.chain.cosine_similarity(v1, v3), 0.0)

    @pytest.mark.asyncio
    async def test_alert_verification_success(self):
        """Test successful alert verification with consensus"""
        alert = {
            'type': 'threat',
            'severity': 'high',
            'source': 'honeypot_12'
        }

        # Generate signatures with >51% support
        signatures = await self.chain.simulate_node_signatures(alert, support_ratio=0.7)

        # Verify alert
        verified = await self.chain.verify_alert(alert, signatures)

        assert verified == True
        assert self.chain.verified_count == 1
        assert len(self.chain.chain) == 2  # Genesis + new block

    @pytest.mark.asyncio
    async def test_alert_verification_failure(self):
        """Test failed alert verification without consensus"""
        alert = {
            'type': 'threat',
            'severity': 'low'
        }

        # Generate signatures with <51% support
        signatures = await self.chain.simulate_node_signatures(alert, support_ratio=0.3)

        # Verify alert (should fail)
        verified = await self.chain.verify_alert(alert, signatures)

        assert verified == False
        assert self.chain.rejected_count == 1
        assert len(self.chain.chain) == 1  # Only genesis block

    @pytest.mark.asyncio
    async def test_block_mining(self):
        """Test proof of work mining"""
        alert = {'type': 'test'}
        signatures = ['sig1', 'sig2']

        block = await self.chain.add_block(alert, signatures)

        assert block is not None
        assert block.calculate_hash().startswith("00")  # Difficulty 2
        assert block.nonce > 0  # Had to mine

    def test_chain_validation(self):
        """Test blockchain integrity validation"""
        # Initially valid
        assert self.chain.validate_chain() == True

        # Add some blocks
        asyncio.run(self._add_test_blocks())

        # Should still be valid
        assert self.chain.validate_chain() == True

        # Tamper with a block
        if len(self.chain.chain) > 1:
            self.chain.chain[1].alert_data['tampered'] = True

            # Should detect tampering
            assert self.chain.validate_chain() == False

    async def _add_test_blocks(self):
        """Helper to add test blocks"""
        for i in range(3):
            alert = {'test_id': i}
            signatures = [f'sig_{i}']
            await self.chain.add_block(alert, signatures)

    @pytest.mark.asyncio
    async def test_broadcast_verified_alert(self):
        """Test broadcasting of verified alerts"""
        alert = {'type': 'broadcast_test'}
        signatures = await self.chain.simulate_node_signatures(alert, 0.7)

        # Verify and add to chain
        await self.chain.verify_alert(alert, signatures)

        # Broadcast
        result = await self.chain.broadcast_verified_alert(alert)

        assert result['status'] == 'broadcast'
        assert 'block_index' in result
        assert result['alert'] == alert

    def test_chain_status(self):
        """Test getting blockchain status"""
        status = self.chain.get_chain_status()

        assert status['chain_length'] == 1  # Genesis
        assert status['verified_alerts'] == 0
        assert status['rejected_alerts'] == 0
        assert status['consensus_threshold'] == 0.51
        assert status['total_nodes'] == 100
        assert status['vector_dimensions'] == 16
        assert status['chain_valid'] == True


class TestVectorConsensus:
    """Test distributed consensus mechanism"""

    def setup_method(self):
        """Setup test fixtures"""
        self.chain = VectorChain(dimensions=16, nodes=10)  # Smaller for testing
        self.consensus = VectorConsensus(self.chain)

    @pytest.mark.asyncio
    async def test_request_consensus_success(self):
        """Test successful consensus request"""
        alert = {'type': 'consensus_test'}

        # Mock node responses to achieve consensus quickly
        with patch.object(self.consensus, 'voting_nodes', {}):
            # Simulate enough votes
            for i in range(6):  # >51% of 10 nodes
                self.consensus.voting_nodes[i] = self.chain.node_vectors[i]

            result = await self.consensus.request_consensus(alert, timeout=1.0)
            assert result == True

    @pytest.mark.asyncio
    async def test_request_consensus_timeout(self):
        """Test consensus timeout"""
        alert = {'type': 'timeout_test'}

        # Don't provide enough votes
        result = await self.consensus.request_consensus(alert, timeout=0.1)
        assert result == False  # Should timeout


class TestBlock:
    """Test individual block functionality"""

    def test_block_creation(self):
        """Test block creation and hashing"""
        block = Block(
            index=1,
            timestamp=time.time(),
            alert_data={'type': 'test'},
            vector_hash='test_hash',
            previous_hash='prev_hash',
            nonce=0,
            signatures=['sig1', 'sig2']
        )

        assert block.index == 1
        assert block.alert_data['type'] == 'test'
        assert len(block.signatures) == 2

    def test_block_hash_calculation(self):
        """Test block hash calculation"""
        block = Block(
            index=1,
            timestamp=1234567890,
            alert_data={'type': 'test'},
            vector_hash='vec_hash',
            previous_hash='prev_hash'
        )

        hash1 = block.calculate_hash()
        assert len(hash1) == 64  # SHA256

        # Same block should produce same hash
        hash2 = block.calculate_hash()
        assert hash1 == hash2

        # Changing data should change hash
        block.alert_data['modified'] = True
        hash3 = block.calculate_hash()
        assert hash3 != hash1


@pytest.mark.asyncio
async def test_vector_chain_performance():
    """Test VectorChain performance metrics"""
    chain = VectorChain(dimensions=16, nodes=100)

    # Measure verification time
    start = time.time()

    alerts = []
    for i in range(10):
        alert = {'id': i, 'type': 'perf_test'}
        signatures = await chain.simulate_node_signatures(alert, 0.7)
        verified = await chain.verify_alert(alert, signatures)
        alerts.append(verified)

    elapsed = time.time() - start

    # Should verify 10 alerts in reasonable time
    assert elapsed < 5.0  # Less than 5 seconds
    assert all(alerts)  # All verified
    assert chain.avg_verification_time > 0

    # Check metrics
    status = chain.get_chain_status()
    assert status['verified_alerts'] == 10
    assert status['avg_verification_time_ms'] < 500  # <500ms per verification


if __name__ == "__main__":
    pytest.main([__file__, '-v', '--tb=short'])