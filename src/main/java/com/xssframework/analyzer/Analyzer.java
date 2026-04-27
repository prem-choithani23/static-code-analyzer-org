package com.xssframework.analyzer;

import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;

import java.util.List;

/**
 * Contract for every file analyzer.
 *
 * An analyzer is responsible for:
 *   1. Accepting a ParsedFile (raw lines + optional AST)
 *   2. Delegating to one or more Detector implementations
 *   3. Collecting and returning all findings
 *
 * Each analyzer is tied to a specific file type (Java, Config, Template).
 */
public interface Analyzer {

    /**
     * Analyse the given parsed file and return all findings.
     *
     * @param parsedFile the file to analyse
     * @return list of findings, possibly empty; never null
     */
    List<Finding> analyze(ParsedFile parsedFile);

}
