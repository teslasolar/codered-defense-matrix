#!/usr/bin/env python3
"""
Simple test validation script for CodeRED Defense Matrix
Verifies that all test files can be imported and basic tests pass
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

def validate_imports():
    """Validate all modules can be imported"""
    print("Validating module imports...")

    modules_to_test = [
        'src.utils.security_core',
        'src.blockchain.vector_chain',
        'src.swarm.swarm_defender',
        'src.core.defense_matrix',
        'src.honeypot.honeypot_net'
    ]

    success = True
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"  [OK] {module}")
        except ImportError as e:
            print(f"  [FAIL] {module}: {e}")
            success = False

    return success


def run_simple_tests():
    """Run simple unit tests without pytest"""
    print("\nRunning simple validation tests...")

    tests_passed = 0
    tests_failed = 0

    # Test 1: AuthenticationSystem
    try:
        from src.utils.security_core import AuthenticationSystem
        auth = AuthenticationSystem()
        assert hasattr(auth, 'authenticate')
        print("  [PASS] AuthenticationSystem initialization")
        tests_passed += 1
    except Exception as e:
        print(f"  [FAIL] AuthenticationSystem: {e}")
        tests_failed += 1

    # Test 2: VectorChain
    try:
        from src.blockchain.vector_chain import VectorChain
        chain = VectorChain(dimensions=16, nodes=10)
        assert len(chain.chain) == 1  # Genesis block
        print("  [PASS] VectorChain initialization")
        tests_passed += 1
    except Exception as e:
        print(f"  [FAIL] VectorChain: {e}")
        tests_failed += 1

    # Test 3: SwarmDefender
    try:
        from src.swarm.swarm_defender import SwarmDefender
        defender = SwarmDefender("test_001", "patrol")
        assert defender.agent_id == "test_001"
        print("  [PASS] SwarmDefender initialization")
        tests_passed += 1
    except Exception as e:
        print(f"  [FAIL] SwarmDefender: {e}")
        tests_failed += 1

    # Test 4: DefenseMatrix
    try:
        from src.core.defense_matrix import DefenseMatrix
        matrix = DefenseMatrix(shape=(10, 10, 10), sparse=True)
        assert matrix.shape == (10, 10, 10)
        print("  [PASS] DefenseMatrix initialization")
        tests_passed += 1
    except Exception as e:
        print(f"  [FAIL] DefenseMatrix: {e}")
        tests_failed += 1

    # Test 5: HoneypotNet
    try:
        from src.honeypot.honeypot_net import HoneypotNet
        honeypots = HoneypotNet(honeypot_count=5)
        assert len(honeypots.honeypots) == 5
        print("  [PASS] HoneypotNet initialization")
        tests_passed += 1
    except Exception as e:
        print(f"  [FAIL] HoneypotNet: {e}")
        tests_failed += 1

    # Test 6: Security Compliance Check
    try:
        from src.utils.security_core import ComplianceEnforcer, SecurityContext, SecurityLevel
        from datetime import datetime, timedelta

        compliance = ComplianceEnforcer()
        context = SecurityContext(
            user_id='test',
            role='analyst',
            clearance_level=SecurityLevel.CONFIDENTIAL,
            authentication_methods=['password', 'totp'],
            session_id='test_session',
            expires_at=datetime.now() + timedelta(hours=1),
            source_ip='127.0.0.1'
        )

        is_compliant, reason = compliance.check_compliance('test_operation', context)
        assert isinstance(is_compliant, bool)
        print("  [PASS] Compliance checking")
        tests_passed += 1
    except Exception as e:
        print(f"  [FAIL] Compliance checking: {e}")
        tests_failed += 1

    print(f"\nResults: {tests_passed} passed, {tests_failed} failed")
    return tests_failed == 0


def check_test_files():
    """Check that test files exist"""
    print("\nChecking test files...")

    test_files = [
        'tests/test_security_core.py',
        'tests/test_vector_chain.py',
        'tests/test_swarm_defender.py',
        'tests/test_integration.py',
        'pytest.ini'
    ]

    all_exist = True
    for file in test_files:
        if Path(file).exists():
            print(f"  [OK] {file}")
        else:
            print(f"  [MISSING] {file}")
            all_exist = False

    return all_exist


def main():
    """Main validation"""
    print("=" * 60)
    print("CodeRED Defense Matrix - Test Validation")
    print("=" * 60)

    # Check Python version
    print(f"\nPython version: {sys.version}")
    if sys.version_info < (3, 8):
        print("[WARNING] Python 3.8+ is recommended")

    # Validate imports
    imports_ok = validate_imports()

    # Check test files
    files_ok = check_test_files()

    # Run simple tests
    tests_ok = run_simple_tests()

    # Summary
    print("\n" + "=" * 60)
    if imports_ok and files_ok and tests_ok:
        print("[SUCCESS] All validations passed!")
        print("\nYou can now run full tests with:")
        print("  - Windows: test_runner.bat")
        print("  - Linux/Mac: pytest tests/")
        print("  - Python: python -m pytest tests/ -v")
        return 0
    else:
        print("[FAILURE] Some validations failed.")
        print("Please check the errors above and fix them.")
        return 1


if __name__ == "__main__":
    sys.exit(main())