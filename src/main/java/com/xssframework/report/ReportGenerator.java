package com.xssframework.report;

import com.xssframework.model.Finding;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Contract for report generators.
 *
 * A report generator transforms a list of findings into a human-readable report
 * (HTML, JSON, etc.) and writes it to disk.
 */
public interface ReportGenerator {

    /**
     * Generate a report from the given findings and write it to the specified path.
     *
     * @param findings   list of vulnerabilities to report
     * @param outputPath where to write the report file
     * @throws IOException if file writing fails
     */
    void generate(List<Finding> findings, Path outputPath) throws IOException;
}
