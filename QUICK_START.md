# Spring Boot Security Analyzer - Quick Start Guide

## 🚀 Installation & Execution

### Prerequisites

- Java 17 or higher
- 6.7 MB disk space for JAR file

### JAR Location

```
target/spring-security-analyzer.jar
```

---

## 📋 Three Ways to Run

### 1️⃣ GUI Mode (Recommended for Interactive Use)

Open a graphical interface with file browser:

```bash
java -jar target/spring-security-analyzer.jar
```

**What happens:**

- Window opens with purple header
- Browse button to select project directory
- Output directory selector (defaults to `project/output/`)
- Custom report naming field (auto-generates if empty)
- Click "Start Analysis" to scan
- Real-time log display shows progress
- Report auto-opens in your default browser when complete

---

### 2️⃣ CLI Mode (Recommended for Automation)

Command-line interface with default output:

```bash
java -jar target/spring-security-analyzer.jar /path/to/my-spring-app
```

**Output:**

- Report saved to: `/path/to/my-spring-app/output/security-analysis-report-YYYY-MM-DD-HHmmss.html`
- Scanning logs printed to console
- Threat summary displayed

---

### 3️⃣ CLI Mode with Custom Report Name

Specify exact output filename:

```bash
java -jar target/spring-security-analyzer.jar /path/to/app my-report.html
```

**Output:**

- Report saved to: `/path/to/app/output/my-report.html`
- All scan details included in report

---

## 📊 What Gets Detected

### 1. **XSS (Cross-Site Scripting)**

- Unsafe `response.write()` calls
- Direct string concatenation in output
- Raw user input in responses

### 2. **SQL Injection**

- Query string concatenation
- Unsafe JDBC statement building
- EntityManager raw query vulnerabilities

### 3. **REST Data Exposure**

- Unsanitized entity responses
- Sensitive fields in @RestController outputs
- Direct entity mapping to HTTP responses

### 4. **Taint Flow (Cross-File Analysis)**

- User input tracking from endpoints to services
- Parameter flow through @RequestParam → @Service → @Repository
- Identifies where untrusted data reaches risky operations

### 5. **Spring Configuration Issues**

- Weak JWT secrets
- Security disabled in configuration
- Actuator endpoints over-exposed
- SSL/HTTPS disabled

### 6. **Template XSS**

- Thymeleaf unsafe `th:utext` attributes
- JSP unsafe EL expressions
- Unescaped template variables

---

## 📈 Sample Output Report

Generated reports include:

- **Executive Summary**
  - Total findings count
  - Breakdown by severity (CRITICAL, HIGH, MEDIUM, LOW)
  - Overall threat score

- **Detailed Findings**
  - Vulnerability type
  - File name and line number
  - Full code snippet
  - Severity level with color coding
  - Description of the issue
  - Recommended fix

- **Interactive Features**
  - Expandable/collapsible findings
  - Copy-to-clipboard code snippets
  - Sortable by threat level

---

## ⚙️ Configuration

No configuration file needed! The tool works out of the box.

**Default Behavior:**

- Scans: `.java`, `.properties`, `.yml`, `.html`, `.jsp` files
- Excludes: `target/`, `build/`, `.git/`, `node_modules/`, `vendor/`
- Output location: `project/output/`
- Report format: Interactive HTML

---

## 💡 Usage Examples

### Example 1: Scan a Local Project

```bash
cd ~/my-spring-app
java -jar ~/static-code-analyzer/target/spring-security-analyzer.jar .
# Report: ~/my-spring-app/output/security-analysis-report-2024-01-15-143022.html
```

### Example 2: Scan with GUI

```bash
java -jar ~/analyzer.jar
# 1. Click "Browse..." for project path
# 2. Select ~/my-spring-app
# 3. Output path auto-defaults to ~/my-spring-app/output
# 4. Enter report name or leave blank for auto-generated
# 5. Click "Start Analysis"
# 6. Report opens automatically in browser
```

### Example 3: CI/CD Integration

```bash
# In your CI pipeline
java -jar analyzer.jar /path/to/repo security-scan.html
# Report: /path/to/repo/output/security-scan.html
```

---

## 📁 Project Structure After Scanning

```
my-spring-app/
├── src/
├── pom.xml
└── output/                    ← Generated here
    └── security-analysis-report-YYYY-MM-DD-HHmmss.html
```

---

## 🔧 Advanced Usage

### Integrate into Build Process

Add to your Maven `pom.xml`:

```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    <executions>
        <execution>
            <phase>verify</phase>
            <goals><goal>exec</goal></goals>
            <configuration>
                <executable>java</executable>
                <arguments>
                    <argument>-jar</argument>
                    <argument>path/to/analyzer.jar</argument>
                    <argument>${project.basedir}</argument>
                </arguments>
            </configuration>
        </execution>
    </executions>
</plugin>
```

### Automate Daily Scans

Create a cron job (Linux/Mac):

```bash
# Add to crontab -e
0 2 * * * java -jar /home/user/analyzer.jar /home/user/projects/app report-$(date +%Y%m%d).html >> /var/log/security-scan.log 2>&1
```

---

## 🐛 Troubleshooting

### GUI doesn't open

```bash
# Ensure you have display available
export DISPLAY=:0
java -jar spring-security-analyzer.jar
```

### Out of Memory

```bash
# Increase heap size
java -Xmx2g -jar spring-security-analyzer.jar /path/to/project
```

### Can't find Java

```bash
# Install Java 17+
# Verify: java -version
# Should show version 17 or higher
```

### Report not generated

- Check permissions in project directory
- Ensure `output/` folder is writable
- Verify project path is absolute
- Check console logs for errors

---

## 📞 Support

For issues or questions:

1. Check the FINAL_STATUS.md for technical details
2. Review generated reports for findings explanations
3. All vulnerability types have fix recommendations in reports

---

## 📜 License

Part of the Static Code Analyzer project.

---

**Last Updated:** 2026-04-28
**Version:** 1.0.0
**Status:** ✅ Production Ready
