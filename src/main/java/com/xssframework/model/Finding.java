package com.xssframework.model;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Immutable record of a single detected vulnerability.
 * Built by detectors; consumed by the report generator.
 * All fields are set at construction — no setters.
 */
public final class Finding {

    private final Path filePath;
    private final int lineNumber;
    private final VulnerabilityType vulnerabilityType;
    private final String description;
    private final int threatScore;           // 1–100
    private final ThreatLevel threatLevel;   // derived from threatScore
    private final String suggestion;
    private final String codeSnippet;        // the offending line(s), may be empty

    private Finding(Builder builder) {
        this.filePath          = Objects.requireNonNull(builder.filePath,          "filePath");
        this.lineNumber        = builder.lineNumber;
        this.vulnerabilityType = Objects.requireNonNull(builder.vulnerabilityType, "vulnerabilityType");
        this.description       = Objects.requireNonNull(builder.description,       "description");
        this.threatScore       = clamp(builder.threatScore);
        this.threatLevel       = ThreatLevel.fromScore(this.threatScore);
        this.suggestion        = builder.suggestion != null ? builder.suggestion : "";
        this.codeSnippet       = builder.codeSnippet != null ? builder.codeSnippet : "";
    }

    private static int clamp(int score) {
        return Math.max(1, Math.min(100, score));
    }

    // ── Getters ─────────────────────────────────────────────────────────────

    public Path getFilePath()                   { return filePath; }
    public int getLineNumber()                  { return lineNumber; }
    public VulnerabilityType getVulnerabilityType() { return vulnerabilityType; }
    public String getDescription()              { return description; }
    public int getThreatScore()                 { return threatScore; }
    public ThreatLevel getThreatLevel()         { return threatLevel; }
    public String getSuggestion()               { return suggestion; }
    public String getCodeSnippet()              { return codeSnippet; }

    @Override
    public String toString() {
        return String.format("[%s | Score:%d | %s:%d] %s",
                vulnerabilityType.getDisplayName(), threatScore,
                filePath.getFileName(), lineNumber, description);
    }

    // ── Builder ─────────────────────────────────────────────────────────────

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Path filePath;
        private int lineNumber;
        private VulnerabilityType vulnerabilityType;
        private String description;
        private int threatScore;
        private String suggestion;
        private String codeSnippet;

        private Builder() {}

        public Builder filePath(Path filePath)         { this.filePath = filePath; return this; }
        public Builder lineNumber(int lineNumber)       { this.lineNumber = lineNumber; return this; }
        public Builder type(VulnerabilityType type)    { this.vulnerabilityType = type; return this; }
        public Builder description(String desc)        { this.description = desc; return this; }
        public Builder threatScore(int score)          { this.threatScore = score; return this; }
        public Builder suggestion(String suggestion)   { this.suggestion = suggestion; return this; }
        public Builder codeSnippet(String snippet)     { this.codeSnippet = snippet; return this; }

        public Finding build() {
            return new Finding(this);
        }
    }
}