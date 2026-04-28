package com.xssframework.detector.template;

import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import com.xssframework.model.VulnerabilityType;
import com.xssframework.scoring.ThreatScorer;
import com.xssframework.suggestion.SuggestionProvider;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects template-layer XSS vulnerabilities in Thymeleaf and JSP files.
 *
 * Detection patterns:
 * 1. th:utext (unescaped Thymeleaf output) — flags as XSS sink
 * 2. Inline ${...} expressions in <script> blocks — bypasses Java-layer
 * sanitization
 * 3. Raw EL expressions in JSP (<%=...%>, <c:out escapeXml="false">)
 * 4. Event handler attributes with ${...} expressions (onclick="${...}")
 */
public final class TemplateXssDetector implements Detector {

    private static final Logger logger = LoggerFactory.getLogger(TemplateXssDetector.class);

    // Patterns to detect unsafe template expressions
    private static final Pattern THYMELEAF_UTEXT_PATTERN = Pattern.compile(
            "th:utext\\s*=\\s*[\"']([^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern EL_EXPRESSION_PATTERN = Pattern.compile(
            "\\$\\{[^}]+\\}");

    private static final Pattern JSP_EXPRESSION_PATTERN = Pattern.compile(
            "<%\\s*=\\s*(.+?)\\s*%>");

    private static final Pattern JSP_UNSAFE_OUT_PATTERN = Pattern.compile(
            "<c:out\\s+value\\s*=\\s*[\"']\\$\\{[^}]+\\}[\"']\\s+escapeXml\\s*=\\s*[\"']false[\"']",
            Pattern.CASE_INSENSITIVE);

    private static final Set<String> SCRIPT_BLOCK_TAGS = Set.of(
            "script", "style");

    private static final Set<String> EVENT_HANDLERS = Set.of(
            "onclick", "onload", "onerror", "onchange", "onmouseover", "onmouseout",
            "onkeydown", "onkeyup", "onsubmit", "onfocus", "onblur");

    @Override
    public List<Finding> detect(ParsedFile parsedFile) {
        List<Finding> findings = new ArrayList<>();

        if (parsedFile.getFileType() == ParsedFile.FileType.THYMELEAF) {
            detectInThymeleaf(parsedFile, findings);
        } else if (parsedFile.getFileType() == ParsedFile.FileType.JSP) {
            detectInJsp(parsedFile, findings);
        }

        return findings;
    }

    @Override
    public boolean supports(ParsedFile.FileType fileType) {
        return fileType == ParsedFile.FileType.THYMELEAF || fileType == ParsedFile.FileType.JSP;
    }

    // ── Thymeleaf detection ──────────────────────────────────────────────────

    private void detectInThymeleaf(ParsedFile parsedFile, List<Finding> findings) {
        List<String> lines = parsedFile.getRawLines();

        for (int lineNum = 0; lineNum < lines.size(); lineNum++) {
            String line = lines.get(lineNum);
            int lineNumber = lineNum + 1;

            // Pattern 1: th:utext (unescaped output)
            if (line.contains("th:utext")) {
                var matcher = THYMELEAF_UTEXT_PATTERN.matcher(line);
                if (matcher.find()) {
                    String expr = matcher.group(1);
                    String desc = String.format(
                            "Thymeleaf th:utext outputs unescaped HTML: '%s'. " +
                                    "Use th:text instead to automatically escape user-controlled content.",
                            expr);
                    addFinding(parsedFile, lineNumber, line, desc, findings);
                }
            }

            // Pattern 2: ${...} inside <script> blocks
            if (isInsideScriptBlock(lines, lineNum)) {
                if (EL_EXPRESSION_PATTERN.matcher(line).find()) {
                    String desc = "EL expression found in <script> block. " +
                            "Inline ${...} in JavaScript can lead to XSS if the expression is user-controlled. " +
                            "Use th:inline=\"javascript\" and th:text for safe variable substitution.";
                    addFinding(parsedFile, lineNumber, line, desc, findings);
                }
            }

            // Pattern 3: Event handlers with ${...}
            if (containsElInEventHandler(line)) {
                String desc = "Event handler attribute contains EL expression: " + line.trim() +
                        ". This can lead to DOM-based XSS. Move event handler logic to JavaScript.";
                addFinding(parsedFile, lineNumber, line, desc, findings);
            }
        }
    }

    // ── JSP detection ────────────────────────────────────────────────────────

    private void detectInJsp(ParsedFile parsedFile, List<Finding> findings) {
        List<String> lines = parsedFile.getRawLines();

        for (int lineNum = 0; lineNum < lines.size(); lineNum++) {
            String line = lines.get(lineNum);
            int lineNumber = lineNum + 1;

            // Pattern 1: <%= ... %> (raw JSP expression)
            if (JSP_EXPRESSION_PATTERN.matcher(line).find()) {
                String desc = "Unescaped JSP expression <%=...%>. If the expression is user-controlled, " +
                        "this is an XSS sink. Use <c:out> with escapeXml=\"true\" instead.";
                addFinding(parsedFile, lineNumber, line, desc, findings);
            }

            // Pattern 2: <c:out escapeXml="false">
            if (JSP_UNSAFE_OUT_PATTERN.matcher(line).find()) {
                String desc = "Unsafe JSP output: <c:out escapeXml=\"false\">. " +
                        "If the output value is user-controlled, this is an XSS sink.";
                addFinding(parsedFile, lineNumber, line, desc, findings);
            }

            // Pattern 3: ${...} in <script> blocks
            if (isInsideScriptBlock(lines, lineNum)) {
                if (EL_EXPRESSION_PATTERN.matcher(line).find()) {
                    String desc = "EL expression found in JSP <script> block. " +
                            "If the expression contains user-controlled data, this is an XSS sink.";
                    addFinding(parsedFile, lineNumber, line, desc, findings);
                }
            }

            // Pattern 4: Event handlers with ${...}
            if (containsElInEventHandler(line)) {
                String desc = "Event handler in JSP contains EL expression. " +
                        "This can lead to DOM-based XSS attacks.";
                addFinding(parsedFile, lineNumber, line, desc, findings);
            }
        }
    }

    // ── Utilities ────────────────────────────────────────────────────────────

    private boolean isInsideScriptBlock(List<String> lines, int currentLineNum) {
        // Simple heuristic: scan backwards for <script> or <style>
        int openCount = 0;
        int closeCount = 0;

        for (int i = currentLineNum; i >= 0; i--) {
            String line = lines.get(i).toLowerCase();
            openCount += countOccurrences(line, "<script");
            closeCount += countOccurrences(line, "</script");
            if (openCount > closeCount)
                return true;
        }

        openCount = 0;
        closeCount = 0;
        for (int i = currentLineNum; i >= 0; i--) {
            String line = lines.get(i).toLowerCase();
            openCount += countOccurrences(line, "<style");
            closeCount += countOccurrences(line, "</style");
            if (openCount > closeCount)
                return true;
        }

        return false;
    }

    private boolean containsElInEventHandler(String line) {
        String lower = line.toLowerCase();
        for (String handler : EVENT_HANDLERS) {
            if (lower.contains(handler + "=") && line.contains("${")) {
                return true;
            }
        }
        return false;
    }

    private int countOccurrences(String text, String substring) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(substring, index)) != -1) {
            count++;
            index += substring.length();
        }
        return count;
    }

    private void addFinding(ParsedFile parsedFile, int lineNum, String codeLine,
            String description, List<Finding> findings) {
        String snippet = codeLine.trim();
        int threatScore = ThreatScorer.score(VulnerabilityType.TEMPLATE_XSS, description);

        findings.add(Finding.builder()
                .filePath(parsedFile.getPath())
                .lineNumber(lineNum)
                .type(VulnerabilityType.TEMPLATE_XSS)
                .description(description)
                .threatScore(threatScore)
                .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.TEMPLATE_XSS, snippet))
                .codeSnippet(snippet)
                .build());

        logger.debug("Found template XSS at {}:{}: {}", parsedFile.getPath(), lineNum, description);
    }
}
