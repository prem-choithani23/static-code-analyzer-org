package com.xssframework.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Main GUI window for the Spring Boot Security Analyzer.
 * Provides file browsing and configuration for security scans.
 */
public class AnalyzerGUI extends JFrame {

    private JTextField projectPathField;
    private JTextField outputPathField;
    private JTextField reportNameField;
    private JButton browseProjectBtn;
    private JButton browseOutputBtn;
    private JButton analyzeBtn;
    private JButton resetBtn;
    private JTextArea logArea;
    private JLabel statusLabel;

    public AnalyzerGUI() {
        setTitle("🔐 Spring Boot Security Analyzer");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setExtendedState(JFrame.MAXIMIZED_BOTH);
        setSize(1400, 900);
        setLocationRelativeTo(null);
        setResizable(true);

        initializeUI();
    }

    private void initializeUI() {
        // Main panel with padding
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        mainPanel.setBackground(new Color(245, 245, 250));

        // Header
        mainPanel.add(createHeaderPanel());
        mainPanel.add(Box.createVerticalStrut(20));

        // Project Path Section
        mainPanel.add(createLabeledPanel("Project Path", createProjectPathPanel()));
        mainPanel.add(Box.createVerticalStrut(15));

        // Output Path Section
        mainPanel.add(createLabeledPanel("Output Path", createOutputPathPanel()));
        mainPanel.add(Box.createVerticalStrut(15));

        // Report Name Section
        mainPanel.add(createLabeledPanel("Report Filename (Optional)", createReportNamePanel()));
        mainPanel.add(Box.createVerticalStrut(20));

        // Buttons
        mainPanel.add(createButtonsPanel());
        mainPanel.add(Box.createVerticalStrut(20));

        // Status
        mainPanel.add(createStatusPanel());
        mainPanel.add(Box.createVerticalStrut(15));

        // Log Area
        mainPanel.add(createLabeledPanel("Analysis Log", createLogPanel()));

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        add(scrollPane);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(new Color(102, 126, 234));
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));

        JLabel titleLabel = new JLabel("Spring Boot Security Analyzer");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 36));
        titleLabel.setForeground(Color.WHITE);

        JLabel descLabel = new JLabel("Detect XSS, SQL Injection, Config Issues & Taint Flows");
        descLabel.setFont(new Font("Segoe UI", Font.PLAIN, 18));
        descLabel.setForeground(new Color(220, 220, 240));

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(descLabel);

        return panel;
    }

    private JPanel createProjectPathPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));

        projectPathField = new JTextField();
        projectPathField.setEditable(false);
        projectPathField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        projectPathField.setBackground(new Color(250, 250, 250));

        browseProjectBtn = new JButton("Browse");
        browseProjectBtn.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        browseProjectBtn.setPreferredSize(new Dimension(120, 45));
        browseProjectBtn.addActionListener(e -> browseProjectDirectory());

        panel.add(projectPathField, BorderLayout.CENTER);
        panel.add(browseProjectBtn, BorderLayout.EAST);

        return panel;
    }

    private JPanel createOutputPathPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));

        outputPathField = new JTextField();
        outputPathField.setEditable(false);
        outputPathField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        outputPathField.setBackground(new Color(250, 250, 250));

        // Set default to project's output folder
        String defaultOutputPath = new File(System.getProperty("user.dir"), "output").getAbsolutePath();
        outputPathField.setText(defaultOutputPath);

        browseOutputBtn = new JButton("Browse");
        browseOutputBtn.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        browseOutputBtn.setPreferredSize(new Dimension(120, 45));
        browseOutputBtn.addActionListener(e -> browseOutputDirectory());

        panel.add(outputPathField, BorderLayout.CENTER);
        panel.add(browseOutputBtn, BorderLayout.EAST);

        return panel;
    }

    private JPanel createReportNamePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));

        reportNameField = new JTextField();
        reportNameField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        reportNameField.setToolTipText(
                "Leave empty for auto-generated name (security-analysis-report-YYYY-MM-DD-HHmmss.html)");

        panel.add(reportNameField, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createButtonsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
        panel.setBackground(new Color(245, 245, 250));

        analyzeBtn = new JButton("🔍 Start Analysis");
        analyzeBtn.setFont(new Font("Segoe UI", Font.BOLD, 16));
        analyzeBtn.setPreferredSize(new Dimension(180, 50));
        analyzeBtn.setBackground(new Color(46, 204, 113));
        analyzeBtn.setForeground(Color.WHITE);
        analyzeBtn.setBorderPainted(false);
        analyzeBtn.setFocusPainted(false);
        analyzeBtn.addActionListener(e -> startAnalysis());

        resetBtn = new JButton("↻ Reset");
        resetBtn.setFont(new Font("Segoe UI", Font.PLAIN, 15));
        resetBtn.setPreferredSize(new Dimension(150, 50));
        resetBtn.setBackground(new Color(200, 200, 200));
        resetBtn.setForeground(Color.BLACK);
        resetBtn.setBorderPainted(false);
        resetBtn.setFocusPainted(false);
        resetBtn.addActionListener(e -> resetFields());

        panel.add(analyzeBtn);
        panel.add(resetBtn);

        return panel;
    }

    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(new Color(245, 245, 250));

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        statusLabel.setForeground(new Color(100, 100, 100));

        panel.add(statusLabel, BorderLayout.WEST);

        return panel;
    }

    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);

        logArea = new JTextArea();
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        logArea.setEditable(false);
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(0, 255, 0));
        logArea.setMargin(new Insets(10, 10, 10, 10));
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));
        scrollPane.setPreferredSize(new Dimension(0, 300));

        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createLabeledPanel(String label, JPanel contentPanel) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(new Color(245, 245, 250));

        JLabel labelComponent = new JLabel(label);
        labelComponent.setFont(new Font("Segoe UI", Font.BOLD, 15));
        labelComponent.setForeground(new Color(50, 50, 50));

        panel.add(labelComponent, BorderLayout.NORTH);
        panel.add(Box.createVerticalStrut(8), BorderLayout.CENTER);
        panel.add(contentPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void browseProjectDirectory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Spring Boot Project");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(false);
        fileChooser.setPreferredSize(new Dimension(1000, 700));

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            projectPathField.setText(selectedFile.getAbsolutePath());
            logArea.append("✓ Project path selected: " + selectedFile.getAbsolutePath() + "\n");
        }
    }

    private void browseOutputDirectory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Output Directory");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(false);
        fileChooser.setPreferredSize(new Dimension(1000, 700));

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            outputPathField.setText(selectedFile.getAbsolutePath());
            logArea.append("✓ Output path selected: " + selectedFile.getAbsolutePath() + "\n");
        }
    }

    private void startAnalysis() {
        // Validation
        String projectPath = projectPathField.getText().trim();
        String outputPath = outputPathField.getText().trim();

        if (projectPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select a project path", "Validation Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (!Files.exists(Paths.get(projectPath))) {
            JOptionPane.showMessageDialog(this, "Project path does not exist", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (outputPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select an output path", "Validation Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Get report filename
        String reportName = reportNameField.getText().trim();
        if (reportName.isEmpty()) {
            reportName = generateDefaultReportName();
        } else if (!reportName.endsWith(".html")) {
            reportName += ".html";
        }

        String reportPath = Paths.get(outputPath, reportName).toString();

        // Update UI
        analyzeBtn.setEnabled(false);
        statusLabel.setText("Analysis in progress...");
        statusLabel.setForeground(new Color(255, 152, 0));
        logArea.append("\n" + "=".repeat(80) + "\n");
        logArea.append("Starting analysis...\n");
        logArea.append("Project: " + projectPath + "\n");
        logArea.append("Output: " + reportPath + "\n");
        logArea.append("=".repeat(80) + "\n\n");

        // Run analysis in separate thread to keep UI responsive
        Thread analysisThread = new Thread(() -> {
            try {
                AnalysisRunner.runAnalysis(projectPath, reportPath, logArea);

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("✓ Analysis complete!");
                    statusLabel.setForeground(new Color(46, 204, 113));
                    analyzeBtn.setEnabled(true);

                    int openReport = JOptionPane.showConfirmDialog(
                            this,
                            "Analysis complete! Open report?",
                            "Success",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.INFORMATION_MESSAGE);

                    if (openReport == JOptionPane.YES_OPTION) {
                        try {
                            Desktop.getDesktop().open(new File(reportPath));
                        } catch (Exception ex) {
                            logArea.append("\n⚠ Could not open report: " + ex.getMessage() + "\n");
                        }
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("✗ Analysis failed");
                    statusLabel.setForeground(new Color(231, 76, 60));
                    analyzeBtn.setEnabled(true);
                    logArea.append("\n❌ ERROR: " + ex.getMessage() + "\n");
                });
            }
        });
        analysisThread.start();
    }

    private void resetFields() {
        projectPathField.setText("");
        reportNameField.setText("");
        logArea.setText("");
        statusLabel.setText("Ready");
        statusLabel.setForeground(new Color(100, 100, 100));
        String defaultOutputPath = new File(System.getProperty("user.dir"), "output").getAbsolutePath();
        outputPathField.setText(defaultOutputPath);
    }

    private String generateDefaultReportName() {
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss"));
        return "security-analysis-report-" + timestamp + ".html";
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            AnalyzerGUI gui = new AnalyzerGUI();
            gui.setVisible(true);
        });
    }
}
