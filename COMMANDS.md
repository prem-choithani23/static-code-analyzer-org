# Spring Boot Security Analyzer - Quick Commands

## 🎯 GUI Mode (Interactive)

### Launch GUI
```bash
java -jar target/spring-security-analyzer.jar
```

**What happens:**
1. Window opens maximized to fill your screen
2. Click "Browse..." to select your Spring Boot project
3. Output path defaults to `project/output/` (or browse to change)
4. Enter optional report filename (auto-generates if empty)
5. Click "🔍 Start Analysis" button
6. Watch real-time logs in the terminal-style log area
7. Report auto-opens in your browser when complete

---

## 💻 Terminal/CLI Mode (Command Line)

### Option 1: Scan with Default Output
```bash
java -jar target/spring-security-analyzer.jar /path/to/my-spring-app
```

**Output:**
- Report: `/path/to/my-spring-app/output/security-analysis-report-YYYY-MM-DD-HHmmss.html`
- Logs printed to console

### Option 2: Scan with Custom Report Name
```bash
java -jar target/spring-security-analyzer.jar /path/to/my-spring-app my-report.html
```

**Output:**
- Report: `/path/to/my-spring-app/output/my-report.html`

### Option 3: Scan Current Directory
```bash
cd /path/to/my-spring-app
java -jar /path/to/analyzer/target/spring-security-analyzer.jar .
```

**Output:**
- Report: `./output/security-analysis-report-YYYY-MM-DD-HHmmss.html`

---

## 📊 Real-World Examples

### Example 1: Analyze a Local Spring Boot App (GUI)
```bash
# Navigate to analyzer directory
cd ~/static-code-analyzer

# Launch GUI
java -jar target/spring-security-analyzer.jar

# In GUI:
# 1. Browse to ~/my-spring-boot-app
# 2. Click Start Analysis
# 3. Wait for completion
# 4. Report opens automatically
```

### Example 2: Analyze a Project (CLI - Fast)
```bash
# Quick analysis from command line
java -jar ~/static-code-analyzer/target/spring-security-analyzer.jar ~/my-spring-app
```

### Example 3: Analyze with Custom Report Name (CLI)
```bash
# Save with specific name
java -jar ~/static-code-analyzer/target/spring-security-analyzer.jar \
  ~/my-spring-app \
  security-scan-2024.html
```

### Example 4: Batch Scanning Multiple Projects (CLI)
```bash
#!/bin/bash
ANALYZER="/path/to/analyzer.jar"

for project in ~/projects/*; do
  if [ -d "$project" ]; then
    echo "Scanning: $project"
    java -jar "$ANALYZER" "$project" "${project##*/}-report.html"
  fi
done
```

---

## 🚀 CI/CD Integration (CLI)

### GitHub Actions
```yaml
- name: Run Security Analysis
  run: |
    java -jar analyzer.jar ${{ github.workspace }} ci-scan-report.html
    
- name: Upload Report
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: output/ci-scan-report.html
```

### GitLab CI
```yaml
security_scan:
  script:
    - java -jar analyzer.jar . gitlab-security-report.html
  artifacts:
    paths:
      - output/gitlab-security-report.html
```

### Jenkins Pipeline
```groovy
stage('Security Analysis') {
    steps {
        sh 'java -jar analyzer.jar . jenkins-scan.html'
        archiveArtifacts 'output/jenkins-scan.html'
    }
}
```

---

## 📋 Command Comparison

| Mode | Speed | Best For | Command |
|------|-------|----------|---------|
| **GUI** | Medium | Interactive, Visual | `java -jar analyzer.jar` |
| **CLI** | Fast | Automation, CI/CD | `java -jar analyzer.jar /path` |
| **CLI Custom** | Fast | Specific naming | `java -jar analyzer.jar /path name.html` |

---

## 🔧 Advanced Usage

### Set Custom Output Location
```bash
# GUI: Use "Browse..." button for output path

# CLI: Create output dir first, then use it
mkdir -p ~/reports
java -jar analyzer.jar /project ~/reports/custom-name.html
```

### Increase Memory for Large Projects
```bash
# If you get out-of-memory errors
java -Xmx2g -jar target/spring-security-analyzer.jar /large-project
```

### Suppress Output (CLI)
```bash
# Redirect logs to file
java -jar analyzer.jar /project > analysis.log 2>&1
```

---

## 📍 Report Locations

**GUI Mode:** Opens in browser automatically
**CLI Mode:** Check these locations:
- `/path/to/project/output/security-analysis-report-*.html`
- Or custom path if specified

---

## ✅ Quick Start Checklist

- [ ] Ensure Java 17+ installed: `java -version`
- [ ] JAR file exists: `ls -l target/spring-security-analyzer.jar`
- [ ] For GUI: `java -jar target/spring-security-analyzer.jar`
- [ ] For CLI: `java -jar target/spring-security-analyzer.jar /path/to/project`
- [ ] Report generated in `output/` folder or custom location

---

**Need Help?** Check the generated HTML report for:
- Vulnerability descriptions
- Code snippets showing the issue
- Recommended fixes for each finding
