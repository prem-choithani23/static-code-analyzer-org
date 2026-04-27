package com.xssframework.model;

import com.github.javaparser.ast.CompilationUnit;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Unified wrapper for a file that has been read from disk.
 *
 * Java files carry a parsed AST (CompilationUnit from JavaParser).
 * Config and template files carry raw lines only.
 * Every analyzer receives a ParsedFile — so ScanEngine never
 * needs to know what kind of file it is routing.
 */
public final class ParsedFile {

    public enum FileType { JAVA, PROPERTIES, YAML, THYMELEAF, JSP, OTHER }

    private final Path path;
    private final List<String> rawLines;
    private final CompilationUnit compilationUnit; // null for non-Java files
    private final FileType fileType;

    public ParsedFile(Path path, List<String> rawLines, CompilationUnit compilationUnit, FileType fileType) {
        this.path              = path;
        this.rawLines          = Collections.unmodifiableList(rawLines);
        this.compilationUnit   = compilationUnit;
        this.fileType          = fileType;
    }

    /** Convenience factory for Java source files */
    public static ParsedFile java(Path path, List<String> lines, CompilationUnit cu) {
        return new ParsedFile(path, lines, cu, FileType.JAVA);
    }

    /** Convenience factory for non-Java text files */
    public static ParsedFile text(Path path, List<String> lines, FileType type) {
        return new ParsedFile(path, lines, null, type);
    }

    public Path getPath()                              { return path; }
    public List<String> getRawLines()                  { return rawLines; }
    public Optional<CompilationUnit> getCompilationUnit() {
        return Optional.ofNullable(compilationUnit);
    }
    public FileType getFileType()                      { return fileType; }
    public boolean isJava()                            { return fileType == FileType.JAVA; }

    /** Zero-indexed line access; returns empty string if out of range */
    public String getLine(int zeroIndexed) {
        if (zeroIndexed < 0 || zeroIndexed >= rawLines.size()) return "";
        return rawLines.get(zeroIndexed);
    }
}