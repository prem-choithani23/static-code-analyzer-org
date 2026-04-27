package com.xssframework.detector;

import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;

import java.util.List;

/**
 * Contract for every detection module.
 *
 * Each detector receives a ParsedFile and returns zero or more findings.
 * Detectors must be stateless — all state lives in TaintGraph.
 * A detector that requires taint state injects TaintGraph at construction.
 */
public interface Detector {

    /**
     * Analyse the given parsed file and return all findings.
     * Never returns null — return an empty list if nothing is found.
     *
     * @param parsedFile the file to analyse (AST + raw lines)
     * @return list of findings, possibly empty
     */
    List<Finding> detect(ParsedFile parsedFile);

    /**
     * Returns true if this detector is applicable to the given file type.
     * ScanEngine uses this to avoid passing Java detectors a YAML file, etc.
     */
    boolean supports(ParsedFile.FileType fileType);
}