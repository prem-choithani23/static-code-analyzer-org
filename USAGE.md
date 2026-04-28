# Usage Guide - Spring Boot Security Analyzer

## Installation

### Option 1: Pre-built JAR

```bash
java -jar spring-security-analyzer.jar /path/to/project
```

### Option 2: Build from Source

```bash
git clone <repo>
cd static-code-analyzer
mvn clean package
java -jar target/spring-security-analyzer.jar /path/to/project
```

## Basic Usage

### Minimal Usage

```bash
java -jar spring-security-analyzer.jar ~/my-spring-app
```

**Output:**

- Auto-generated report: `security-analysis-report-YYYY-MM-DD-HHmmss.html`
- Console output with scan summary

### Custom Report Path

```bash
java -jar spring-security-analyzer.jar ~/my-spring-app ./reports/scan-2026-04-27.html
```

### With Logging

```bash
java -jar spring-security-analyzer.jar ~/my-spring-app 2>&1 | tee scan.log
```

## Understanding the Report

### Color Coding

| Level    | Color  | Score  | Meaning         |
| -------- | ------ | ------ | --------------- |
| CRITICAL | Red    | 90–100 | Fix immediately |
| HIGH     | Orange | 70–89  | High priority   |
| MEDIUM   | Yellow | 40–69  | Address soon    |
| LOW      | Green  | 1–39   | Minor issues    |

### Reading a Finding

1. **Click** a row to expand details
2. **Score**: Numeric threat rank (higher = worse)
3. **Type**: Category of vulnerability
4. **File & Line**: Location in source code
5. **Snippet**: Exact problematic code
6. **Suggestion**: How to fix it

### Example Findings

#### XSS - Unsafe Response Output

```
File: UserController.java:42
Code: response.getWriter().write(user.getBio());
Fix: Use HtmlUtils.htmlEscape(user.getBio())
```

#### SQL Injection - String Concatenation

```
File: UserRepository.java:18
Code: "SELECT * FROM users WHERE id = " + userId
Fix: Use @Query with @Param binding
```

#### Insecure Config - Weak JWT Secret

```
File: application.properties:5
Code: jwt.secret=supersecret
Fix: Use >= 32 character entropy, store in env vars
```

## Advanced Usage

### Scanning Subdirectories

Scan a specific module in a multi-module project:

```bash
java -jar spring-security-analyzer.jar ~/my-app/backend
```

### CI/CD Integration

#### GitHub Actions

```yaml
- name: Security Scan
  run: |
    java -jar spring-security-analyzer.jar . ./report.html
    echo "Report: $(pwd)/report.html"
```

#### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh 'java -jar spring-security-analyzer.jar . ./report.html'
        publishHTML([
            reportDir: '.',
            reportFiles: 'report.html',
            reportName: 'Security Report'
        ])
    }
}
```

#### GitLab CI

```yaml
security_scan:
  script:
    - java -jar spring-security-analyzer.jar . report.html
  artifacts:
    paths:
      - report.html
```

## Interpreting Results

### No Findings Found ✅

- Project passed security scan
- Check README for false negative scenarios

### Many Findings 🔴

**Recommended action plan:**

1. Sort by CRITICAL/HIGH
2. Start with most common types
3. Fix in order of threat score
4. Re-run tool to verify

### False Positives

Some tools flag conservative patterns. Our tool aims for **zero false positives** through:

- AST-based analysis (not naive string matching)
- Context awareness (e.g., test profiles vs. production)
- Sanitizer detection

If you find a false positive, note:

- File and line number
- Code snippet
- Why you believe it's false

## Troubleshooting

### "Project root path does not exist"

```
Solution: Verify the path exists
$ ls -la /path/to/project
```

### "Failed to parse Java AST"

```
Issue: Malformed Java syntax
Solution: Ensure project compiles locally
$ mvn clean compile
```

### "Out of Memory" (for very large projects)

```bash
# Increase heap size
java -Xmx4g -jar spring-security-analyzer.jar /path
```

### No findings in Large Project

```
Possible issues:
1. Project doesn't use detected patterns
2. Scan didn't reach certain directories
3. Check logs for warnings about skipped files
```

## Configuration

### Environment Variables (Reserved for Future)

```bash
# To support future AI suggestions:
export XSS_ANALYZER_AI_KEY=<api-key>
java -jar spring-security-analyzer.jar /path
```

## Report Customization (Future Versions)

Currently, HTML report is fixed. Future versions will support:

- [ ] Custom CSS theming
- [ ] Report format options (JSON, CSV, SARIF)
- [ ] Filtering by vulnerability type
- [ ] Baseline comparison (current vs. previous scan)

## Performance Tips

### For Large Codebases (500+ files)

```bash
# Recommended minimum:
java -Xmx2g -jar spring-security-analyzer.jar /path

# Typical runtime:
- < 100 files:   1–3 seconds
- 100–500 files: 5–15 seconds
- 500+ files:    20–60 seconds
```

### Excluding Directories

Currently, these are auto-excluded:

- `target/`, `build/`, `dist/`
- `.git/`, `.idea/`, `.gradle/`, `.vscode/`
- `node_modules/`
- `*.class`, `*.jar` files

To scan a specific module:

```bash
java -jar analyzer.jar ./backend/src
```

## Best Practices

### Development Workflow

1. **Pre-commit**: Run tool before pushing
2. **PR validation**: Include scan in CI/CD
3. **Weekly scan**: Track trends over time

### Fix Prioritization

1. **CRITICAL** — Block PR merge
2. **HIGH** — Fix within sprint
3. **MEDIUM** — Backlog item
4. **LOW** — Nice-to-have

### Baseline Tracking

```bash
# Generate timestamped reports
java -jar analyzer.jar . ./reports/scan-$(date +%Y-%m-%d).html

# Compare reports manually (or via future tooling)
```

---

**For more details, see [README.md](README.md)**
