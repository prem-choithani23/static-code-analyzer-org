package com.xssframework.model;

/**
 * Maps a numeric threat score (1–100) to a severity label.
 * Used in the HTML report for colour-coding and sorting.
 */
public enum ThreatLevel {

    CRITICAL(90, 100, "#c0392b", "CRITICAL"),
    HIGH    (70,  89, "#e67e22", "HIGH"),
    MEDIUM  (40,  69, "#f1c40f", "MEDIUM"),
    LOW     ( 1,  39, "#27ae60", "LOW");

    private final int minScore;
    private final int maxScore;
    private final String hexColour;
    private final String label;

    ThreatLevel(int minScore, int maxScore, String hexColour, String label) {
        this.minScore   = minScore;
        this.maxScore   = maxScore;
        this.hexColour  = hexColour;
        this.label      = label;
    }

    /**
     * Resolves the ThreatLevel for a given numeric score.
     * Scores outside 1–100 are clamped to LOW.
     */
    public static ThreatLevel fromScore(int score) {
        for (ThreatLevel level : values()) {
            if (score >= level.minScore && score <= level.maxScore) {
                return level;
            }
        }
        return LOW;
    }

    public int getMinScore() { return minScore; }
    public int getMaxScore() { return maxScore; }
    public String getHexColour() { return hexColour; }
    public String getLabel() { return label; }
}