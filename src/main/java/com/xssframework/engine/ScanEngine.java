package com.xssframework.engine;

import com.xssframework.analyzer.*;
import com.xssframework.detector.Detector;
import com.xssframework.detector.config.SpringConfigDetector;
import com.xssframework.detector.java.*;
import com.xssframework.detector.template.TemplateXssDetector;
import com.xssframework.engine.findings.FileTreeWalker;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import com.xssframework.taint.TaintGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Orchestrates the complete security scanning pipeline.
 *
 * Responsibilities:
 * 1. Walk the project file tree (via FileTreeWalker)
 * 2. Route each file to the appropriate analyzer based on file type
 * 3. Maintain TaintGraph state across scans (for cross-file taint tracking)
 * 4. Collect all findings from detectors
 * 5. Sort findings by threat score (descending) before returning
 *
 * Flow:
 * ScanEngine.scan(rootPath)
 * → FileTreeWalker.walk(fileConsumer)
 * → For each ParsedFile: route to Analyzer
 * → Analyzer delegates to Detector(s)
 * → ScanEngine collects all findings
 * → Return sorted list
 */
public final class ScanEngine {

    private static final Logger logger = LoggerFactory.getLogger(ScanEngine.class);

    private final TaintGraph taintGraph;
    private final Map<ParsedFile.FileType, Analyzer> analyzers;

    public ScanEngine() {
        this.taintGraph = new TaintGraph();
        this.analyzers = new ConcurrentHashMap<>();

        // Create detector instances
        List<Detector> javaDetectors = new ArrayList<>();
        javaDetectors.add(new XssDetector());
        javaDetectors.add(new SqlInjectionDetector());
        javaDetectors.add(new RestSanitizationDetector());
        javaDetectors.add(new TaintFlowDetector(taintGraph));

        List<Detector> configDetectors = new ArrayList<>();
        configDetectors.add(new SpringConfigDetector());

        List<Detector> templateDetectors = new ArrayList<>();
        templateDetectors.add(new TemplateXssDetector());

        // Register analyzers
        this.analyzers.put(ParsedFile.FileType.JAVA, new JavaSourceAnalyzer(javaDetectors));
        this.analyzers.put(ParsedFile.FileType.PROPERTIES, new ConfigFileAnalyzer(configDetectors));
        this.analyzers.put(ParsedFile.FileType.YAML, new ConfigFileAnalyzer(configDetectors));
        this.analyzers.put(ParsedFile.FileType.THYMELEAF, new TemplateAnalyzer(templateDetectors));
        this.analyzers.put(ParsedFile.FileType.JSP, new TemplateAnalyzer(templateDetectors));
    }

    /**
     * Execute a complete scan of the given project root directory.
     *
     * @param projectRootPath the root path to scan (e.g., /home/user/my-spring-app)
     * @return sorted list of all findings (descending by threat score)
     * @throws IOException if file traversal or parsing fails
     */
    public List<Finding> scan(Path projectRootPath) throws IOException {
        logger.info("Starting security scan of project: {}", projectRootPath);

        if (!Files.exists(projectRootPath)) {
            throw new IOException("Project root path does not exist: " + projectRootPath);
        }

        List<Finding> allFindings = Collections.synchronizedList(new ArrayList<>());
        FileTreeWalker walker = new FileTreeWalker(projectRootPath);

        // Walk the file tree and process each file
        walker.walk(parsedFile -> {
            try {
                List<Finding> findings = analyzeFile(parsedFile);
                allFindings.addAll(findings);
                logger.debug("Analyzed {}: found {} vulnerabilities", parsedFile.getPath(), findings.size());
            } catch (Exception e) {
                logger.warn("Error analyzing file {}: {}", parsedFile.getPath(), e.getMessage());
            }
        });

        // Sort by threat score (descending)
        List<Finding> sorted = allFindings.stream()
                .sorted(Comparator.comparingInt(Finding::getThreatScore).reversed())
                .collect(Collectors.toList());

        logger.info("Scan complete. Total findings: {}", sorted.size());
        return sorted;
    }

    // ── File analysis ────────────────────────────────────────────────────────

    private List<Finding> analyzeFile(ParsedFile parsedFile) {
        Analyzer analyzer = analyzers.get(parsedFile.getFileType());
        if (analyzer == null) {
            logger.debug("No analyzer for file type: {}", parsedFile.getFileType());
            return Collections.emptyList();
        }
        return analyzer.analyze(parsedFile);
    }

    /**
     * Get the current taint graph (for test/debug purposes).
     */
    public TaintGraph getTaintGraph() {
        return taintGraph;
    }

    /**
     * Clear the taint graph (useful for sequential scans).
     */
    public void clearTaintGraph() {
        taintGraph.clear();
    }
}
