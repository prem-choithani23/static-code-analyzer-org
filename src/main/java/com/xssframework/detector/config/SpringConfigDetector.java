package com.xssframework.detector.config;

import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import com.xssframework.model.VulnerabilityType;
import com.xssframework.scoring.ThreatScorer;
import com.xssframework.suggestion.SuggestionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects insecure Spring configuration in application.properties and application.yml files.
 *
 * Detection patterns:
 *   1. Weak JWT secrets (< 32 characters)
 *   2. spring.security.enabled=false in any profile
 *   3. management.endpoints.web.exposure.include=* (Actuator over-exposure)
 *   4. server.ssl.enabled=false in non-dev profiles
 *   5. Hardcoded database passwords
 *   6. Other weak security settings
 */
public final class SpringConfigDetector implements Detector {

    private static final Logger logger = LoggerFactory.getLogger(SpringConfigDetector.class);

    // Regex patterns for detecting weak secrets
    private static final Pattern JWT_SECRET_PATTERN = Pattern.compile(
            "^\\s*(?:jwt\\.secret|app\\.jwt\\.secret|spring\\.security\\.jwt\\.secret)\\s*=\\s*(.*)$",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern WEAK_PASSWORD_PATTERN = Pattern.compile(
            "^\\s*(?:spring\\.datasource\\.password|db\\.password|app\\.db\\.password)\\s*=\\s*(.*)$",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SECURITY_DISABLED_PATTERN = Pattern.compile(
            "^\\s*spring\\.security\\.enabled\\s*=\\s*false\\s*$",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ACTUATOR_EXPOSED_PATTERN = Pattern.compile(
            "^\\s*management\\.endpoints\\.web\\.exposure\\.include\\s*=\\s*\\*\\s*$",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SSL_DISABLED_PATTERN = Pattern.compile(
            "^\\s*server\\.ssl\\.enabled\\s*=\\s*false\\s*$",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public List<Finding> detect(ParsedFile parsedFile) {
        List<Finding> findings = new ArrayList<>();

        if (parsedFile.getFileType() == ParsedFile.FileType.PROPERTIES) {
            detectInProperties(parsedFile, findings);
        } else if (parsedFile.getFileType() == ParsedFile.FileType.YAML) {
            detectInYaml(parsedFile, findings);
        }

        return findings;
    }

    @Override
    public boolean supports(ParsedFile.FileType fileType) {
        return fileType == ParsedFile.FileType.PROPERTIES || fileType == ParsedFile.FileType.YAML;
    }

    // ── Properties file detection ────────────────────────────────────────────

    private void detectInProperties(ParsedFile parsedFile, List<Finding> findings) {
        List<String> lines = parsedFile.getRawLines();
        String fileName = parsedFile.getPath().getFileName().toString();
        boolean isDevProfile = fileName.contains("-dev");

        for (int lineNum = 0; lineNum < lines.size(); lineNum++) {
            String line = lines.get(lineNum);
            int lineNumber = lineNum + 1;

            // Skip comments and empty lines
            if (line.trim().isEmpty() || line.trim().startsWith("#")) continue;

            // Check JWT secret weakness
            var jwtMatcher = JWT_SECRET_PATTERN.matcher(line);
            if (jwtMatcher.find()) {
                String secretValue = jwtMatcher.group(1).trim().replaceAll("^['\"]|['\"]$", "");
                if (secretValue.length() < 32) {
                    String desc = String.format(
                            "Weak JWT secret found: '%s' is only %d characters. " +
                                    "JWT secrets should be at least 256 bits (32 characters) of high entropy.",
                            secretValue, secretValue.length()
                    );
                    addFinding(parsedFile, lineNumber, desc, findings);
                }
            }

            // Check security disabled
            if (SECURITY_DISABLED_PATTERN.matcher(line).find()) {
                String desc = "Spring Security is disabled: spring.security.enabled=false. " +
                        "This must never appear in production profiles.";
                addFinding(parsedFile, lineNumber, desc, findings);
            }

            // Check Actuator over-exposure
            if (ACTUATOR_EXPOSED_PATTERN.matcher(line).find()) {
                String desc = "Actuator endpoints are fully exposed: management.endpoints.web.exposure.include=*. " +
                        "This exposes sensitive operational endpoints publicly.";
                addFinding(parsedFile, lineNumber, desc, findings);
            }

            // Check SSL disabled in non-dev profiles
            if (SSL_DISABLED_PATTERN.matcher(line).find() && !isDevProfile) {
                String desc = "SSL/TLS is disabled: server.ssl.enabled=false. " +
                        "TLS must be enforced in all non-development environments.";
                addFinding(parsedFile, lineNumber, desc, findings);
            }

            // Check weak database password
            var pwdMatcher = WEAK_PASSWORD_PATTERN.matcher(line);
            if (pwdMatcher.find()) {
                String pwdValue = pwdMatcher.group(1).trim().replaceAll("^['\"]|['\"]$", "");
                if (pwdValue.length() < 12 || !containsMixedCase(pwdValue)) {
                    String desc = "Weak database password detected: password is too simple or too short.";
                    addFinding(parsedFile, lineNumber, desc, findings);
                }
            }
        }
    }

    // ── YAML file detection ──────────────────────────────────────────────────

    private void detectInYaml(ParsedFile parsedFile, List<Finding> findings) {
        try {
            String content = String.join("\n", parsedFile.getRawLines());
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(content);

            if (data != null) {
                detectInYamlMap(data, parsedFile, 1, findings);
            }
        } catch (Exception e) {
            logger.warn("Failed to parse YAML file {}: {}", parsedFile.getPath(), e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void detectInYamlMap(Map<String, Object> map, ParsedFile parsedFile, int lineNum,
                                 List<Finding> findings) {
        if (map == null) return;

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey().toLowerCase();
            Object value = entry.getValue();

            // Check JWT secret
            if (key.contains("jwt") && key.contains("secret") && value instanceof String) {
                String secretValue = (String) value;
                if (secretValue.length() < 32) {
                    String desc = String.format(
                            "Weak JWT secret in YAML: value is only %d characters. " +
                                    "JWT secrets should be at least 256 bits (32 characters).",
                            secretValue.length()
                    );
                    addFinding(parsedFile, lineNum, desc, findings);
                }
            }

            // Check security enabled
            if (key.contains("security") && key.contains("enabled") && value instanceof Boolean) {
                if (!(Boolean) value) {
                    String desc = "Spring Security is disabled in YAML configuration.";
                    addFinding(parsedFile, lineNum, desc, findings);
                }
            }

            // Check SSL enabled
            if (key.contains("ssl") && key.contains("enabled") && value instanceof Boolean) {
                if (!(Boolean) value && !parsedFile.getPath().getFileName().toString().contains("dev")) {
                    String desc = "SSL/TLS is disabled in YAML. TLS must be enforced in production.";
                    addFinding(parsedFile, lineNum, desc, findings);
                }
            }

            // Recurse into nested maps
            if (value instanceof Map) {
                detectInYamlMap((Map<String, Object>) value, parsedFile, lineNum, findings);
            }
        }
    }

    // ── Utilities ────────────────────────────────────────────────────────────

    private void addFinding(ParsedFile parsedFile, int lineNum, String description, List<Finding> findings) {
        String snippet = parsedFile.getLine(lineNum - 1).trim();
        int threatScore = ThreatScorer.score(VulnerabilityType.INSECURE_CONFIG, description);

        findings.add(Finding.builder()
                .filePath(parsedFile.getPath())
                .lineNumber(lineNum)
                .type(VulnerabilityType.INSECURE_CONFIG)
                .description(description)
                .threatScore(threatScore)
                .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.INSECURE_CONFIG, snippet))
                .codeSnippet(snippet)
                .build());
    }

    private boolean containsMixedCase(String s) {
        return s.matches(".*[a-z].*") && s.matches(".*[A-Z].*");
    }
}
