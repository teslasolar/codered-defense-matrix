---
title: Source Code
icon: 📦
description: Core implementation of the CodeRED Defense Matrix system
section: Source Code
---

# Source Code Structure

The `src` directory contains all the core implementation code for the CodeRED Defense Matrix system. Each module is designed to work independently while integrating seamlessly with the complete defense framework.

## Core Modules

{{cards:start}}

### 🔐 Security Core
**Location:** `utils/security_core.py`

Multi-factor authentication system with AES-256 encryption, tamper detection, and audit logging. This module provides the fundamental security layer for all other components.

{{badge:success:Active}} {{badge:primary:88 Tests Passing}}

### ⛓️ VectorChain
**Location:** `blockchain/vector_chain.py`

Blockchain-based alert verification system using 16-dimensional vector embeddings for consensus. Prevents false alerts and ensures message integrity across the network.

{{badge:success:Active}} {{badge:warning:Beta}}

### 🤖 SwarmDefender
**Location:** `swarm/swarm_defender.py`

AI-powered defensive agents that autonomously detect and respond to multi-agent threats. Features memory management, pattern recognition, and coordinated defense strategies.

{{badge:success:Active}} {{badge:primary:Production Ready}}

### 🗺️ DefenseMatrix
**Location:** `core/defense_matrix.py`

3D spatial defense grid (1000×1000×1000) for monitoring and protecting infrastructure assets. Real-time threat visualization and response coordination.

{{badge:warning:In Development}}

### 🎭 HoneypotNet
**Location:** `honeypot/honeypot_net.py`

Advanced deception network for early threat detection and intelligence gathering. Creates realistic decoy services to attract and analyze attackers.

{{badge:success:Active}}

{{cards:end}}

## Quick Start

### Running the Main System

```bash
# From the codered-defense-matrix directory
python src/main.py
```

### Quick Deploy with SwarmDefender

```python
# Quick deployment script available
python src/swarm/quick_deploy.py --agents 10 --mode defensive
```

## Module Dependencies

| Module | Dependencies | Python Version |
|--------|-------------|----------------|
| security_core | cryptography, bcrypt | 3.8+ |
| vector_chain | numpy, hashlib | 3.8+ |
| swarm_defender | asyncio, random | 3.8+ |
| defense_matrix | numpy, asyncio | 3.8+ |
| honeypot_net | asyncio, socket | 3.8+ |

## Directory Structure

```
src/
├── blockchain/          # Blockchain verification
│   └── vector_chain.py
├── core/               # Core defense matrix
│   └── defense_matrix.py
├── honeypot/           # Deception network
│   └── honeypot_net.py
├── swarm/              # AI defensive agents
│   ├── swarm_defender.py
│   └── quick_deploy.py
├── utils/              # Utilities and security
│   └── security_core.py
└── main.py             # Main entry point
```

## Development Guidelines

1. **Security First**: All code must pass security validation
2. **Defensive Only**: No offensive capabilities allowed
3. **Test Coverage**: Minimum 80% test coverage required
4. **Documentation**: All functions must be documented
5. **Audit Logging**: All critical operations must be logged

## Testing

Run tests for specific modules:

```bash
# Test security core
pytest tests/test_security_core.py -v

# Test all modules
python run_tests.py
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing to the source code.

## License

All source code is licensed under the MIT License. See [LICENSE](../LICENSE) for details.