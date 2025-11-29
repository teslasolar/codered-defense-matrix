#!/bin/bash

################################################################################
# Push CodeRED Defense Matrix to GitHub
# Ensures all files are properly committed and pushed
################################################################################

echo "========================================="
echo "  CodeRED Defense Matrix - GitHub Push"
echo "========================================="

# Check if we're in the right directory
if [ ! -f "README.md" ] || [ ! -d "src" ]; then
    echo "[ERROR] Not in CodeRED Defense Matrix directory!"
    exit 1
fi

# Show current status
echo ""
echo "[*] Current Git Status:"
git status --short

# Add all important files
echo ""
echo "[*] Adding all project files..."

# Add source code
git add src/
git add tests/

# Add documentation
git add README.md
git add SECURITY.md
git add CONTRIBUTING.md
git add LICENSE
git add docs/

# Add configuration files
git add requirements.txt
git add pytest.ini
git add .gitignore
git add Dockerfile
git add docker-compose.yml

# Add deployment scripts
git add deployment/
git add launch.sh
git add *.py
git add *.bat

# Add configs
git add configs/ 2>/dev/null || true

# Check what's been staged
echo ""
echo "[*] Files staged for commit:"
git status --short | grep "^[AM]" | wc -l
echo ""

# Show what will be committed
git status --short | grep "^[AM]" | head -20

echo ""
read -p "Do you want to commit these changes? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Commit with message
    echo "[*] Committing changes..."
    git commit -m "Complete CodeRED Defense Matrix implementation

- Comprehensive defensive cybersecurity system
- Multi-layer authentication and encryption
- VectorChain blockchain verification
- SwarmDefender AI agents
- DefenseMatrix 3D grid system
- HoneypotNet deception layer
- Full test suite with 88+ tests
- Docker deployment ready
- Security-hardened for defensive use only"

    # Set remote if not set
    if ! git remote | grep -q "origin"; then
        echo "[*] Setting remote origin..."
        git remote add origin https://github.com/teslasolar/codered-defense-matrix.git
    fi

    # Push to GitHub
    echo ""
    echo "[*] Pushing to GitHub..."
    git push -u origin main || git push -u origin master

    echo ""
    echo "========================================="
    echo "[SUCCESS] Pushed to GitHub!"
    echo "Repository: https://github.com/teslasolar/codered-defense-matrix"
    echo ""
    echo "Next steps:"
    echo "1. Go to: https://github.com/teslasolar/codered-defense-matrix/settings/pages"
    echo "2. Enable GitHub Pages from main/master branch"
    echo "3. Your documentation will be at: https://teslasolar.github.io/codered-defense-matrix/"
    echo "========================================="
else
    echo "[*] Commit cancelled"
fi