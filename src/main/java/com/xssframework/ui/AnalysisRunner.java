package com.xssframework.ui;

import com.xssframework.engine.ScanEngine;
import com.xssframework.model.Finding;
import com.xssframework.report.HtmlReportGenerator;

import javax.swing.*;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Handles the actual analysis execution for the GUI.
 * Bridges between the UI and the analysis engine.
 */
public class AnalysisRunner {

    public static void runAnalysis(String projectPath, String reportPath, JTextArea logArea) throws IOException {
        try {
            Path projectRootPath = Paths.get(projectPath);
            Path outputPath = Paths.get(reportPath);

            logArea.append("Initializing scanner...\n");
            ScanEngine engine = new ScanEngine();

            logArea.append("Starting security scan...\n");
            long startTime = System.currentTimeMillis();
            List<Finding> findings = engine.scan(projectRootPath);
            long scanTime = System.currentTimeMillis() - startTime;

            logArea.append("Scan completed in " + scanTime + " ms\n");
            logArea.append("Found " + findings.size() + " vulnerabilities\n\n");

            // Breakdown by threat level
            long critical = findings.stream()
                    .filter(f -> f.getThreatLevel().name().equals("CRITICAL"))
                    .count();
            long high = findings.stream()
                    .filter(f -> f.getThreatLevel().name().equals("HIGH"))
                    .count();
            long medium = findings.stream()
                    .filter(f -> f.getThreatLevel().name().equals("MEDIUM"))
                    .count();
            long low = findings.stream()
                    .filter(f -> f.getThreatLevel().name().equals("LOW"))
                    .count();

            logArea.append("Breakdown:\n");
            logArea.append("  🔴 CRITICAL: " + critical + "\n");
            logArea.append("  🟠 HIGH:     " + high + "\n");
            logArea.append("  🟡 MEDIUM:   " + medium + "\n");
            logArea.append("  🟢 LOW:      " + low + "\n\n");

            logArea.append("Generating HTML report...\n");
            long reportStart = System.currentTimeMillis();
            new HtmlReportGenerator().generate(findings, outputPath);
            long reportTime = System.currentTimeMillis() - reportStart;

            logArea.append("Report generated in " + reportTime + " ms\n\n");
            logArea.append("Report saved to:\n");
            logArea.append(reportPath + "\n");
            logArea.append("\n✅ Analysis complete!");

        } catch (Exception e) {
            logArea.append("\n❌ ERROR: " + e.getMessage() + "\n");
            throw new IOException("Analysis failed", e);
        }
    }
}
