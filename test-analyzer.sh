#!/bin/bash
# Quick verification script for Spring Boot Security Analyzer

set -e

PROJECT_ROOT="$(pwd)"
ANALYZER_JAR="${PROJECT_ROOT}/target/spring-security-analyzer.jar"

echo "======================================"
echo "Spring Boot Security Analyzer - Tester"
echo "======================================"
echo ""

# Check if JAR exists
if [ ! -f "$ANALYZER_JAR" ]; then
    echo "❌ ERROR: JAR not found at $ANALYZER_JAR"
    echo "Please run: mvn clean package"
    exit 1
fi

echo "✅ JAR found: $ANALYZER_JAR"
echo "   Size: $(ls -lh "$ANALYZER_JAR" | awk '{print $5}')"
echo ""

# Test 1: Help/Usage
echo "Test 1: Testing CLI argument validation..."
OUTPUT=$(java -jar "$ANALYZER_JAR" 2>&1 || true)
if echo "$OUTPUT" | grep -q "Usage:"; then
    echo "✅ PASS: CLI help message works"
else
    echo "❌ FAIL: CLI help message not found"
fi
echo ""

# Test 2: Scan current project (this project!)
echo "Test 2: Scanning this project..."
REPORT_PATH="/tmp/test-scan-$$.html"
java -jar "$ANALYZER_JAR" "$(pwd)/src/main/java" "$REPORT_PATH"

if [ -f "$REPORT_PATH" ]; then
    SIZE=$(ls -lh "$REPORT_PATH" | awk '{print $5}')
    echo "✅ PASS: Report generated at $REPORT_PATH ($SIZE)"
    
    # Check if HTML is valid
    if grep -q "<!DOCTYPE html>" "$REPORT_PATH"; then
        echo "✅ PASS: Report contains valid HTML"
    else
        echo "❌ FAIL: Report HTML is invalid"
    fi
    
    # Check for report content
    if grep -q "Security Scan Report" "$REPORT_PATH"; then
        echo "✅ PASS: Report title found"
    else
        echo "❌ FAIL: Report title not found"
    fi
    
    if grep -q "Total Findings\|Detected Vulnerabilities" "$REPORT_PATH"; then
        echo "✅ PASS: Report structure is valid"
    else
        echo "❌ FAIL: Report structure is invalid"
    fi
else
    echo "❌ FAIL: Report not generated"
fi
echo ""

# Test 3: Verify it handles non-existent paths gracefully
echo "Test 3: Testing error handling..."
OUTPUT=$(java -jar "$ANALYZER_JAR" "/nonexistent/path" 2>&1 || true)
if echo "$OUTPUT" | grep -qi "does not exist\|error"; then
    echo "✅ PASS: Error handling works"
else
    echo "❌ FAIL: Error not properly reported"
fi
echo ""

echo "======================================"
echo "Verification Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Open the HTML report in a browser:"
echo "   file://$(realpath $REPORT_PATH)"
echo ""
echo "2. Run on your own project:"
echo "   java -jar $ANALYZER_JAR /path/to/your/spring/project"
echo ""
