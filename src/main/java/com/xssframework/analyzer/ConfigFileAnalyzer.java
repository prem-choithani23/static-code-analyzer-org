package com.xssframework.analyzer;

import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Analyzes Spring configuration files for security issues.
 *
 * Responsibilities:
 *   1. Accept ParsedFile for application.properties, application.yml files
 *   2. Delegate to configuration detectors (SpringConfigDetector)
 *   3. Flag weak JWT secrets, disabled SSL, Actuator over-exposure, etc.
 *
 * Detectors registered:
 *   - SpringConfigDetector (application.properties / application.yml)
 */
public final class ConfigFileAnalyzer implements Analyzer {

    private static final Logger logger = LoggerFactory.getLogger(ConfigFileAnalyzer.class);
    private final List<Detector> detectors;

    public ConfigFileAnalyzer(List<Detector> detectors) {
        this.detectors = detectors != null ? detectors : new ArrayList<>();
    }

    @Override
    public List<Finding> analyze(ParsedFile parsedFile) {
        ParsedFile.FileType type = parsedFile.getFileType();
        if (type != ParsedFile.FileType.PROPERTIES && type != ParsedFile.FileType.YAML) {
            logger.warn("ConfigFileAnalyzer received non-config file: {}", parsedFile.getPath());
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
