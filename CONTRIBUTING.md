# Contributing to CodeRED Defense Matrix

Thank you for your interest in contributing to the CodeRED Defense Matrix! This project aims to protect critical infrastructure from multi-AI swarm attacks, and your contributions can help save lives and protect essential services.

## Code of Conduct

By participating in this project, you agree to:
- Use this software for defensive purposes only
- Report vulnerabilities responsibly
- Treat all contributors with respect
- Focus on protecting, not attacking, infrastructure

## How to Contribute

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email security@codered-defense.org with details
2. Include "SECURITY" in the subject line
3. Provide detailed steps to reproduce
4. Allow 30 days for a response before public disclosure

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version, etc.)
   - Relevant logs or error messages

### Suggesting Enhancements

1. Check if the enhancement has been suggested
2. Create an issue labeled "enhancement" with:
   - Use case description
   - Proposed solution
   - Alternative solutions considered
   - Potential impact on existing functionality

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow coding standards**:
   ```python
   # Good: Descriptive names and comments
   async def detect_swarm_pattern(self, traffic_data: List[Packet]) -> bool:
       """Detect coordinated swarm attack patterns in network traffic"""

   # Bad: Unclear naming
   def det_swrm(self, data):
   ```

3. **Write tests** for new functionality:
   ```python
   async def test_swarm_detection():
       defender = SwarmDefender("test_agent")
       attack_traffic = generate_swarm_traffic()
       result = await defender.detect_swarm_pattern(attack_traffic)
       assert result == True
   ```

4. **Update documentation** for API changes
5. **Run tests** before submitting:
   ```bash
   pytest tests/
   ```

6. **Create pull request** with:
   - Clear title and description
   - Link to related issues
   - Screenshots/logs if applicable

## Priority Areas

We especially welcome contributions in:

### 1. Machine Learning Models
- Improved anomaly detection algorithms
- Lightweight models for edge deployment
- Adversarial attack resistance

### 2. Honeypot Templates
- Industrial control system emulation
- IoT device honeypots
- Cloud service honeypots

### 3. Protocol Support
- Additional industrial protocols (OPC-UA, BACnet)
- IoT protocols (ZigBee, Z-Wave)
- Blockchain integrations

### 4. Deployment Options
- Kubernetes operators
- Cloud provider integrations (AWS, Azure, GCP)
- Edge computing support

### 5. Visualization
- Real-time attack dashboards
- 3D threat visualization
- Mobile monitoring apps

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/codered-defense-matrix.git
   cd codered-defense-matrix
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Run tests**:
   ```bash
   pytest tests/ -v
   ```

5. **Run linting**:
   ```bash
   flake8 src/
   black src/ --check
   ```

## Testing Guidelines

### Unit Tests
- Test individual components in isolation
- Mock external dependencies
- Aim for >80% code coverage

### Integration Tests
- Test component interactions
- Use realistic data scenarios
- Test error handling

### Performance Tests
- Ensure <1s response time for threat detection
- Verify memory usage stays under limits
- Test with 1000+ concurrent connections

## Documentation Standards

### Code Documentation
```python
def deploy_swarm(self, position: Tuple[int, int, int],
                 swarm_size: int = 100) -> Dict[str, Any]:
    """
    Deploy defensive swarm at specified position.

    Args:
        position: 3D coordinate (x, y, z) for deployment
        swarm_size: Number of defenders to deploy (default: 100)

    Returns:
        Dict containing deployment status and metadata

    Raises:
        InvalidPositionError: If position is outside grid bounds
        InsufficientResourcesError: If not enough defenders available

    Example:
        >>> matrix = DefenseMatrix()
        >>> result = await matrix.deploy_swarm((50, 50, 50), 100)
        >>> print(result['status'])
        'deployed'
    """
```

### API Documentation
- Include request/response examples
- Document error codes
- Provide curl examples

## Commit Guidelines

Use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `perf:` Performance improvements
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: add quantum-resistant encryption to VectorChain
fix: prevent memory leak in SwarmDefender patrol mode
docs: update deployment guide for Kubernetes
```

## Release Process

1. Ensure all tests pass
2. Update version in `setup.py`
3. Update CHANGELOG.md
4. Create release PR
5. After merge, tag release: `git tag -a v1.2.3 -m "Release v1.2.3"`
6. Push tags: `git push origin v1.2.3`

## Getting Help

- **Discord**: Join our community server (link in README)
- **Discussions**: Use GitHub Discussions for questions
- **Email**: dev@codered-defense.org

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project website

## Legal

By contributing, you agree that your contributions will be licensed under the MIT License.

## Emergency Response

If you discover an active attack using techniques this system defends against:

1. Deploy immediate-protection.sh
2. Contact CISA: https://www.cisa.gov/report
3. Document the attack pattern
4. Submit PR with detection rules

---

Remember: We're building defenses to protect critical infrastructure and save lives. Every contribution matters. Thank you for helping make the world's infrastructure more resilient!