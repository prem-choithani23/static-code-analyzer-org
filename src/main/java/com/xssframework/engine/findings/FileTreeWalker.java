package com.xssframework.engine.findings;

import com.xssframework.model.ParsedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Recursively traverses a project directory tree and routes files to a
 * consumer.
 *
 * Supports:
 * - .java files
 * - application.properties, application-*.properties
 * - application.yml, application-*.yml
 * - .html (Thymeleaf templates)
 * - .jsp files
 *
 * Skips:
 * - target/, .git/, .idea/, node_modules/, build directories
 * - Binary files, class files, compiled artifacts
 *
 * Thread-safe via ConcurrentHashMap for visited paths.
 */
public final class FileTreeWalker {

    private static final Logger logger = LoggerFactory.getLogger(FileTreeWalker.class);

    private static final Set<String> EXCLUDED_DIRS = Set.of(
            "target", ".git", ".idea", ".gradle", "build", "dist", "out",
            "node_modules", ".mvn", ".vscode", ".DS_Store");

    private static final Set<String> INCLUDED_EXTENSIONS = Set.of(
            ".java", ".properties", ".yml", ".yaml", ".html", ".jsp", ".jspx");

    private static final Set<String> CONFIG_FILE_NAMES = Set.of(
            "application.properties", "application.yml", "application.yaml");

    private final Path rootPath;
    private final Set<Path> visitedDirs = ConcurrentHashMap.newKeySet();

    public FileTreeWalker(Path rootPath) {
        this.rootPath = rootPath;
    }

    /**
     * Recursively walk the directory tree from rootPath, invoking
     * the consumer for each recognized file.
     *
     * @param fileConsumer callback for each ParsedFile found
     * @throws IOException if traversal fails
     */
    public void walk(Consumer<ParsedFile> fileConsumer) throws IOException {
        logger.info("Starting file tree walk from: {}", rootPath);
        walkRecursive(rootPath, fileConsumer);
        logger.info("File tree walk completed. Visited {} directories.", visitedDirs.size());
    }

    // ── Recursive traversal ──────────────────────────────────────────────────

    private void walkRecursive(Path dir, Consumer<ParsedFile> fileConsumer) throws IOException {
        if (visitedDirs.contains(dir)) {
            return; // Avoid cycles
        }
        visitedDirs.add(dir);

        // Skip excluded directories
        String dirName = dir.getFileName().toString();
        if (EXCLUDED_DIRS.contains(dirName)) {
            logger.debug("Skipping excluded directory: {}", dir);
            return;
        }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path entry : stream) {
                if (Files.isDirectory(entry)) {
                    walkRecursive(entry, fileConsumer);
                } else if (Files.isRegularFile(entry)) {
                    processFile(entry, fileConsumer);
                }
            }
        } catch (IOException e) {
            logger.warn("Error traversing directory {}: {}", dir, e.getMessage());
        }
    }

    private void processFile(Path filePath, Consumer<ParsedFile> fileConsumer) {
        String fileName = filePath.getFileName().toString();
        String extension = getExtension(fileName);

        // Check for config files by exact name or extension
        if (isConfigFile(fileName) || isRelevantFile(extension)) {
            try {
                ParsedFile parsedFile = parseFile(filePath);
                fileConsumer.accept(parsedFile);
            } catch (Exception e) {
                logger.warn("Failed to parse file {}: {}", filePath, e.getMessage());
            }
        }
    }

    // ── File type detection ──────────────────────────────────────────────────

    private boolean isConfigFile(String fileName) {
        return CONFIG_FILE_NAMES.contains(fileName) ||
                (fileName.startsWith("application-") &&
                        (fileName.endsWith(".properties") || fileName.endsWith(".yml") || fileName.endsWith(".yaml")));
    }

    private boolean isRelevantFile(String extension) {
        return INCLUDED_EXTENSIONS.contains(extension);
    }

    private String getExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        return lastDot >= 0 ? fileName.substring(lastDot) : "";
    }

    // ── File parsing ─────────────────────────────────────────────────────────

    private ParsedFile parseFile(Path filePath) throws IOException {
        List<String> lines = Files.readAllLines(filePath);
        String extension = getExtension(filePath.getFileName().toString());

        return switch (extension) {
            case ".java" -> ParsedFile.java(filePath, lines, parseJavaSource(filePath, lines));
            case ".properties" -> ParsedFile.text(filePath, lines, ParsedFile.FileType.PROPERTIES);
            case ".yml", ".yaml" -> ParsedFile.text(filePath, lines, ParsedFile.FileType.YAML);
            case ".html" -> ParsedFile.text(filePath, lines, ParsedFile.FileType.THYMELEAF);
            case ".jsp", ".jspx" -> ParsedFile.text(filePath, lines, ParsedFile.FileType.JSP);
            default -> ParsedFile.text(filePath, lines, ParsedFile.FileType.OTHER);
        };
    }

    private com.github.javaparser.ast.CompilationUnit parseJavaSource(Path filePath, List<String> lines)
            throws IOException {
        String source = String.join("\n", lines);
        try {
            return com.github.javaparser.StaticJavaParser.parse(source);
        } catch (Exception e) {
            logger.warn("Failed to parse Java AST for {}: {}", filePath, e.getMessage());
            throw new IOException("AST parsing failed", e);
        }
    }
}
