#!/bin/bash

# Script to sync SentrySearch code to official GitHub repo
# Excludes Hugging Face Spaces specific files

set -e  # Exit on any error

# Define paths
SOURCE_DIR="/Users/michaelrico/SentrySearch"
TARGET_DIR="/Users/michaelrico/Projects/sentrysearch"

# Files to exclude (Hugging Face Spaces specific)
EXCLUDE_FILES=(
    ".space"
    "spaces.md"
)

echo "🔄 Syncing SentrySearch to official GitHub repo..."
echo "Source: $SOURCE_DIR"
echo "Target: $TARGET_DIR"

# Check if target directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "❌ Target directory does not exist: $TARGET_DIR"
    exit 1
fi

# Check if target is a git repo
if [ ! -d "$TARGET_DIR/.git" ]; then
    echo "❌ Target directory is not a git repository: $TARGET_DIR"
    exit 1
fi

# Create temporary directory for filtered sync
TEMP_DIR=$(mktemp -d)
echo "📁 Using temporary directory: $TEMP_DIR"

# Copy all files except .git
echo "📋 Copying source files..."
rsync -av --exclude='.git' "$SOURCE_DIR/" "$TEMP_DIR/"

# Remove Hugging Face specific files from temp directory
echo "🗑️  Removing Hugging Face specific files..."
for file in "${EXCLUDE_FILES[@]}"; do
    if [ -f "$TEMP_DIR/$file" ]; then
        echo "  - Removing: $file"
        rm -f "$TEMP_DIR/$file"
    fi
done

# Remove Hugging Face header from README.md if it exists
if [ -f "$TEMP_DIR/README.md" ]; then
    if head -n 1 "$TEMP_DIR/README.md" | grep -q "^---$"; then
        echo "📝 Removing Hugging Face metadata from README.md"
        sed -i '' '1,11d' "$TEMP_DIR/README.md"
    fi
fi

# Sync filtered content to target directory
echo "📋 Syncing filtered content to target repository..."
rsync -av --delete --exclude='.git' "$TEMP_DIR/" "$TARGET_DIR/"

# Clean up temp directory
rm -rf "$TEMP_DIR"

echo "✅ Sync completed successfully!"
echo ""
echo "📍 To commit and push changes:"
echo "1. cd $TARGET_DIR"
echo "2. git add ."
echo "3. git commit -m 'Add performance optimizations and clean up project structure'"
echo "4. git push origin main"