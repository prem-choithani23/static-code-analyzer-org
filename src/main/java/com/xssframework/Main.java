package com.xssframework;

import com.xssframework.engine.ScanEngine;
import com.xssframework.model.Finding;
import com.xssframework.report.HtmlReportGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Entry point for the Spring Boot Security Analyzer.
 *
 * Usage:
 *   java -jar spring-security-analyzer.jar /path/to/spring/project [output-report.html]
 *
 * If no output path is specified, the report will be written to:
 *   ./security-analysis-report-YYYY-MM-DD-HHmmss.html
 *
 * The scanner will:
 *   1. Recursively traverse all files in the project root
 *   2. Identify and parse Java, config, and template files
 *   3. Execute all security detectors
 *   4. Generate a professional HTML report sorted by threat score
 *   5. Output the report path to stdout
 */
public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        try {
            String projectRoot = args[0];
            String reportPath = args.length > 1 ? args[1] : generateDefaultReportPath();

            run(projectRoot, reportPath);
        } catch (Exception e) {
            logger.error("Fatal error: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    private static void run(String projectRoot, String reportPath) throws IOException {
        logger.info("╔════════════════════════════════════════════════════════════════╗");
        logger.info("║  Spring Boot Security Analyzer - Static Code Analysis          ║");
        logger.info("║  Detecting XSS, SQL Injection, Config Issues, & Taint Flows    ║");
        logger.info("╚════════════════════════════════════════════════════════════════╝");

        Path projectPath = Paths.get(projectRoot);
        if (!Files.exists(projectPath)) {
            throw new IOException("Project root does not exist: " + projectRoot);
        }

        logger.info("Starting scan of project: {}", projectPath.toAbsolutePath());

        // Run the scanner
        ScanEngine engine = new ScanEngine();
        long startTime = System.currentTimeMillis();
        List<Finding> findings = engine.scan(projectPath);
        long scanTime = System.currentTimeMillis() - startTime;

        logger.info("Scan completed in {} ms", scanTime);
        logger.info("Found {} vulnerabilities", findings.size());

        // Generate report
        Path outputPath = Paths.get(reportPath);
        Files.createDirectories(outputPath.getParent());

        long reportStart = System.currentTimeMillis();
        new HtmlReportGenerator().generate(findings, outputPath);
        long reportTime = System.currentTimeMillis() - reportStart;

        logger.info("Report generated in {} ms", reportTime);
        logger.info("═══════════════════════════════════════════════════════════════");
        logger.info("✅ Analysis complete!");
        logger.info("📊 Report: {}", outputPath.toAbsolutePath());
        logger.info("═══════════════════════════════════════════════════════════════");

        // Print to stdout for CI/CD integration
        System.out.println("");
        System.out.println("Report generated: " + outputPath.toAbsolutePath());
        System.out.println("Total findings: " + findings.size());
        System.out.println("Scan time: " + scanTime + " ms");
    }

    private static String generateDefaultReportPath() {
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss"));
        return String.format("output/security-analysis-report-%s.html", timestamp);
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java -jar spring-security-analyzer.jar <project-root> [output-report.html]");
        System.err.println("");
        System.err.println("Arguments:");
        System.err.println("  project-root        (required) Path to the Spring Boot project to scan");
        System.err.println("  output-report.html  (optional) Path where the HTML report will be written");
        System.err.println("                      Default: security-analysis-report-YYYY-MM-DD-HHmmss.html");
        System.err.println("");
        System.err.println("Example:");
        System.err.println("  java -jar spring-security-analyzer.jar /home/user/my-spring-app ./report.html");
    }
}
