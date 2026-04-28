package com.xssframework.analyzer;

import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Analyzes HTML template files for template-layer XSS vulnerabilities.
 *
 * Responsibilities:
 * 1. Accept ParsedFile for .html (Thymeleaf) and .jsp template files
 * 2. Delegate to template detectors (TemplateXssDetector)
 * 3. Flag th:utext, inline ${} in script blocks, raw EL expressions
 *
 * Detectors registered:
 * - TemplateXssDetector (Thymeleaf .html and JSP .jsp files)
 */
public final class TemplateAnalyzer implements Analyzer {

    private static final Logger logger = LoggerFactory.getLogger(TemplateAnalyzer.class);
    private final List<Detector> detectors;

    public TemplateAnalyzer(List<Detector> detectors) {
        this.detectors = detectors != null ? detectors : new ArrayList<>();
    }

    @Override
    public List<Finding> analyze(ParsedFile parsedFile) {
        ParsedFile.FileType type = parsedFile.getFileType();
        if (type != ParsedFile.FileType.THYMELEAF && type != ParsedFile.FileType.JSP) {
            logger.warn("TemplateAnalyzer received non-template file: {}", parsedFile.getPath());
            return new ArrayList<>();
        }

        List<Finding> allFindings = new ArrayList<>();

        for (Detector detector : detectors) {
            if (!detector.supports(type)) {
                continue;
            }
            try {
                List<Finding> findings = detector.detect(parsedFile);
                allFindings.addAll(findings);
                logger.debug("Detector {} found {} findings in {}",
                        detector.getClass().getSimpleName(), findings.size(), parsedFile.getPath());
            } catch (Exception e) {
                logger.warn("Detector {} failed on {}: {}",
                        detector.getClass().getSimpleName(), parsedFile.getPath(), e.getMessage());
            }
        }

        return allFindings;
    }
}
