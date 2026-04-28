package com.xssframework.analyzer;

import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Analyzes Java source files for vulnerabilities.
 *
 * Responsibilities:
 * 1. Accept a ParsedFile with a compiled AST (JavaParser CompilationUnit)
 * 2. Delegate to all registered Java detectors
 * 3. Aggregate findings from all detectors
 *
 * Detectors registered:
 * - XssDetector
 * - SqlInjectionDetector
 * - RestSanitizationDetector
 * - TaintFlowDetector
 */
public final class JavaSourceAnalyzer implements Analyzer {

    private static final Logger logger = LoggerFactory.getLogger(JavaSourceAnalyzer.class);
    private final List<Detector> detectors;

    public JavaSourceAnalyzer(List<Detector> detectors) {
        this.detectors = detectors != null ? detectors : new ArrayList<>();
    }

    @Override
    public List<Finding> analyze(ParsedFile parsedFile) {
        if (parsedFile.getFileType() != ParsedFile.FileType.JAVA) {
            logger.warn("JavaSourceAnalyzer received non-Java file: {}", parsedFile.getPath());
            return new ArrayList<>();
        }

        List<Finding> allFindings = new ArrayList<>();

        for (Detector detector : detectors) {
            if (!detector.supports(ParsedFile.FileType.JAVA)) {
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
