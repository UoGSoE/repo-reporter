#!/bin/bash
# Quick start script for Code Reporter
# Run this after setting up your .env file

set -e

echo "🚀 Code Reporter - Quick Start"
echo "================================"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found!"
    echo "   Please copy .env.example to .env and configure your API keys:"
    echo "   cp .env.example .env"
    echo "   # Then edit .env with your actual API keys"
    exit 1
fi

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ uv is not installed!"
    echo "   Please install uv first: https://docs.astral.sh/uv/"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
uv sync

# Check configuration
echo "🔍 Checking configuration..."
uv run python -m code_reporter.cli --help > /dev/null
if [ $? -eq 0 ]; then
    echo "✅ Configuration looks good!"
else
    echo "❌ Configuration error - please check your .env file"
    exit 1
fi

# Run analysis with example repos
echo "📊 Running analysis with example repositories..."
echo "   This will analyze a few popular projects and generate reports in ./reports"
echo ""

uv run python -m code_reporter.cli \
    --repo-list-file repos.example.txt \
    --output-dir reports \
    --format both \
    --verbose

echo ""
echo "🎉 Analysis complete!"
echo "📄 Check the reports directory for HTML and PDF files"
echo "🌐 Open reports/executive_summary.html in your browser"