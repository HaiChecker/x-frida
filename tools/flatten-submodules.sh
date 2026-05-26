#!/bin/bash
#
# Convert all git submodules into regular directories
# so the entire project can live in a single repository.
#
# This script:
# 1. Deinits all submodules (removes .git linkage)
# 2. Removes .gitmodules
# 3. Stages everything as regular files
#
# After running this, you can push the whole tree to a single repo.
#
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[*] Converting submodules to regular directories..."
echo ""

# Step 1: Get list of all submodule paths (including nested)
find_all_gitmodules() {
    find . -name ".gitmodules" -not -path "./.git/*" | while read f; do
        dir=$(dirname "$f")
        grep "path = " "$f" | awk '{print $3}' | while read p; do
            echo "$dir/$p" | sed 's|^\./||'
        done
    done
}

SUBMODULES=$(find_all_gitmodules | sort -r)  # reverse so nested ones go first

echo "[*] Found submodules:"
echo "$SUBMODULES" | sed 's/^/    /'
echo ""

# Step 2: For each submodule, remove the .git file/directory and deregister
for sm in $SUBMODULES; do
    if [ -e "$sm/.git" ]; then
        echo "[*] Absorbing: $sm"
        # Remove the .git file (it's a pointer to ../.git/modules/xxx)
        rm -f "$sm/.git"
        # Remove nested .gitmodules if present
        if [ -f "$sm/.gitmodules" ]; then
            rm -f "$sm/.gitmodules"
        fi
    fi
done

# Step 3: Remove top-level .gitmodules
if [ -f ".gitmodules" ]; then
    echo "[*] Removing .gitmodules"
    rm -f .gitmodules
fi

# Step 4: Remove .git/modules cache (submodule metadata)
if [ -d ".git/modules" ]; then
    echo "[*] Removing .git/modules/"
    rm -rf .git/modules
fi

# Step 5: Remove submodule entries from git index
echo "[*] Removing submodule entries from git index..."
for sm in $SUBMODULES; do
    git rm --cached "$sm" 2>/dev/null || true
done
git rm --cached .gitmodules 2>/dev/null || true

# Step 6: Add everything as regular files
echo "[*] Staging all files..."
git add -A

echo ""
echo "[*] Done. All submodules are now regular directories."
echo ""
echo "Next steps:"
echo "  git commit -m 'monorepo: absorb all submodules into single repository'"
echo "  git remote add x-frida git@haichecker.github.com:HaiChecker/x-frida.git"
echo "  git push -u x-frida main"
