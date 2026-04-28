package com.xssframework.report;

import com.xssframework.model.Finding;
import com.xssframework.model.ThreatLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates a professional HTML report of security findings.
 *
 * Design:
 * - Clean, modern UI with Bootstrap-like styling
 * - Summary statistics (total findings, breakdown by threat level)
 * - Color-coded findings table (red for CRITICAL, orange for HIGH, etc.)
 * - Sortable by threat score (descending by default)
 * - Expandable detail pane for each finding (file, line, suggestion)
 * - Responsive design for viewing on different screen sizes
 */
public final class HtmlReportGenerator implements ReportGenerator {

    private static final Logger logger = LoggerFactory.getLogger(HtmlReportGenerator.class);

    @Override
    public void generate(List<Finding> findings, Path outputPath) throws IOException {
        String html = buildHtmlReport(findings);
        Files.write(outputPath, html.getBytes(StandardCharsets.UTF_8));
        logger.info("HTML report generated: {}", outputPath);
    }

    private String buildHtmlReport(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();

        // HTML Header + CSS
        sb.append(buildHtmlHeader());

        // Report Title & Summary
        sb.append(buildSummarySection(findings));

        // Findings Table
        sb.append(buildFindingsTable(findings));

        // HTML Footer
        sb.append(buildHtmlFooter());

        return sb.toString();
    }

    private String buildHtmlHeader() {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Security Scan Report</title>
                    <style>
                        * {
                            margin: 0;
                            padding: 0;
                            box-sizing: border-box;
                        }
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            padding: 20px;
                        }
                        .container {
                            max-width: 1400px;
                            margin: 0 auto;
                            background: white;
                            border-radius: 8px;
                            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
                            overflow: hidden;
                        }
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 40px;
                            text-align: center;
                        }
                        .header h1 {
                            font-size: 2.5em;
                            margin-bottom: 10px;
                        }
                        .header p {
                            font-size: 1.1em;
                            opacity: 0.9;
                        }
                        .content {
                            padding: 40px;
                        }
                        .summary {
                            display: grid;
                            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                            gap: 20px;
                            margin-bottom: 40px;
                        }
                        .summary-card {
                            background: #f8f9fa;
                            border-left: 4px solid #667eea;
                            padding: 20px;
                            border-radius: 4px;
                            text-align: center;
                        }
                        .summary-card h3 {
                            color: #667eea;
                            font-size: 2em;
                            margin-bottom: 10px;
                        }
                        .summary-card p {
                            color: #666;
                            font-size: 0.9em;
                        }
                        .summary-card.critical { border-left-color: #c0392b; }
                        .summary-card.critical h3 { color: #c0392b; }
                        .summary-card.high { border-left-color: #e67e22; }
                        .summary-card.high h3 { color: #e67e22; }
                        .summary-card.medium { border-left-color: #f1c40f; }
                        .summary-card.medium h3 { color: #f1c40f; }
                        .summary-card.low { border-left-color: #27ae60; }
                        .summary-card.low h3 { color: #27ae60; }

                        .findings-section h2 {
                            color: #333;
                            margin-bottom: 20px;
                            font-size: 1.8em;
                            border-bottom: 2px solid #667eea;
                            padding-bottom: 10px;
                        }

                        table {
                            width: 100%;
                            border-collapse: collapse;
                            margin-top: 20px;
                        }

                        th {
                            background: #f8f9fa;
                            color: #333;
                            padding: 15px;
                            text-align: left;
                            font-weight: 600;
                            border-bottom: 2px solid #ddd;
                        }

                        td {
                            padding: 15px;
                            border-bottom: 1px solid #eee;
                        }

                        tr:hover {
                            background: #f8f9fa;
                        }

                        .threat-badge {
                            display: inline-block;
                            padding: 6px 12px;
                            border-radius: 4px;
                            font-weight: 600;
                            font-size: 0.85em;
                            color: white;
                        }

                        .threat-critical { background: #c0392b; }
                        .threat-high { background: #e67e22; }
                        .threat-medium { background: #f1c40f; color: #333; }
                        .threat-low { background: #27ae60; }

                        .score {
                            font-weight: 600;
                            text-align: center;
                            font-size: 1.1em;
                        }

                        .file-path {
                            font-family: 'Courier New', monospace;
                            font-size: 0.9em;
                            color: #666;
                        }

                        .code-snippet {
                            font-family: 'Courier New', monospace;
                            background: #f5f5f5;
                            padding: 10px;
                            border-radius: 4px;
                            font-size: 0.85em;
                            overflow-x: auto;
                            margin: 10px 0;
                        }

                        .suggestion {
                            background: #e3f2fd;
                            border-left: 4px solid #2196f3;
                            padding: 12px;
                            margin: 10px 0;
                            border-radius: 4px;
                            font-size: 0.9em;
                            line-height: 1.6;
                        }

                        .no-findings {
                            text-align: center;
                            padding: 40px;
                            color: #27ae60;
                            font-size: 1.2em;
                        }

                        .footer {
                            background: #f8f9fa;
                            padding: 20px;
                            text-align: center;
                            color: #666;
                            font-size: 0.9em;
                            border-top: 1px solid #ddd;
                        }

                        .expandable-row {
                            cursor: pointer;
                        }

                        .details {
                            display: none;
                        }

                        .details.show {
                            display: table-row;
                        }

                        .details td {
                            padding: 20px;
                            background: #fafafa;
                        }
                    </style>
                </head>
                <body>
                <div class="container">
                """;
    }

    private String buildSummarySection(List<Finding> findings) {
        int total = findings.size();
        long critical = findings.stream().filter(f -> f.getThreatLevel() == ThreatLevel.CRITICAL).count();
        long high = findings.stream().filter(f -> f.getThreatLevel() == ThreatLevel.HIGH).count();
        long medium = findings.stream().filter(f -> f.getThreatLevel() == ThreatLevel.MEDIUM).count();
        long low = findings.stream().filter(f -> f.getThreatLevel() == ThreatLevel.LOW).count();

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        return String.format("""
                <div class="header">
                    <h1>🔐 Security Scan Report</h1>
                    <p>Spring Boot Static Code Analysis</p>
                    <p style="margin-top: 10px; font-size: 0.9em;">Generated: %s</p>
                </div>

                <div class="content">
                    <div class="summary">
                        <div class="summary-card">
                            <h3>%d</h3>
                            <p>Total Findings</p>
                        </div>
                        <div class="summary-card critical">
                            <h3>%d</h3>
                            <p>Critical</p>
                        </div>
                        <div class="summary-card high">
                            <h3>%d</h3>
                            <p>High</p>
                        </div>
                        <div class="summary-card medium">
                            <h3>%d</h3>
                            <p>Medium</p>
                        </div>
                        <div class="summary-card low">
                            <h3>%d</h3>
                            <p>Low</p>
                        </div>
                    </div>
                """, timestamp, total, critical, high, medium, low);
    }

    private String buildFindingsTable(List<Finding> findings) {
        if (findings.isEmpty()) {
            return "<div class=\"findings-section\"><h2>Findings</h2><div class=\"no-findings\">✅ No security vulnerabilities detected!</div></div>";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("""
                    <div class="findings-section">
                        <h2>Detected Vulnerabilities</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th style="width: 50px;">Score</th>
                                    <th style="width: 120px;">Threat Level</th>
                                    <th>Vulnerability Type</th>
                                    <th>File</th>
                                    <th>Line</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                """);

        for (Finding finding : findings) {
            String levelClass = findingClassByLevel(finding.getThreatLevel());
            String filePathShort = shortenPath(finding.getFilePath().toString());
            String typeDisplay = finding.getVulnerabilityType().getDisplayName();

            sb.append(String.format("""
                            <tr class="expandable-row" onclick="toggleDetails(this)">
                                <td class="score">%d</td>
                                <td><span class="threat-badge threat-%s">%s</span></td>
                                <td>%s</td>
                                <td class="file-path">%s</td>
                                <td>%d</td>
                                <td>%s</td>
                            </tr>
                            <tr class="details">
                                <td colspan="6">
                                    <div>
                                        <strong>Full File Path:</strong>
                                        <div class="file-path">%s</div>
                                    </div>
                                    <div style="margin-top: 15px;">
                                        <strong>Description:</strong>
                                        <p style="margin-top: 5px; line-height: 1.6;">%s</p>
                                    </div>
                                    <div style="margin-top: 15px;">
                                        <strong>Code Snippet:</strong>
                                        <div class="code-snippet">%s</div>
                                    </div>
                                    <div style="margin-top: 15px;">
                                        <strong>Fix Suggestion:</strong>
                                        <div class="suggestion">%s</div>
                                    </div>
                                </td>
                            </tr>
                    """,
                    finding.getThreatScore(),
                    levelClass,
                    finding.getThreatLevel().getLabel(),
                    escapeHtml(typeDisplay),
                    escapeHtml(filePathShort),
                    finding.getLineNumber(),
                    escapeHtml(truncate(finding.getDescription(), 80)),
                    escapeHtml(finding.getFilePath().toString()),
                    escapeHtml(finding.getDescription()),
                    escapeHtml(finding.getCodeSnippet()),
                    escapeHtml(finding.getSuggestion())));
        }

        sb.append("""
                            </tbody>
                        </table>
                    </div>
                """);

        return sb.toString();
    }

    private String buildHtmlFooter() {
        return """
                </div>
                    <div class="footer">
                        <p>🛡️ Spring Boot Security Analyzer | Static Code Analysis Tool</p>
                        <p>For more information, visit the project repository.</p>
                    </div>
                </div>

                <script>
                    function toggleDetails(row) {
                        const details = row.nextElementSibling;
                        if (details && details.classList.contains('details')) {
                            details.classList.toggle('show');
                        }
                    }
                </script>
                </body>
                </html>
                """;
    }

    // ── Utilities ────────────────────────────────────────────────────────────

    private String findingClassByLevel(ThreatLevel level) {
        return switch (level) {
            case CRITICAL -> "critical";
            case HIGH -> "high";
            case MEDIUM -> "medium";
            case LOW -> "low";
        };
    }

    private String shortenPath(String fullPath) {
        String[] parts = fullPath.replace("\\", "/").split("/");
        if (parts.length > 3) {
            return "..." + "/" + parts[parts.length - 2] + "/" + parts[parts.length - 1];
        }
        return fullPath;
    }

    private String truncate(String text, int maxLen) {
        return text.length() > maxLen ? text.substring(0, maxLen) + "..." : text;
    }

    private String escapeHtml(String text) {
        if (text == null)
            return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
