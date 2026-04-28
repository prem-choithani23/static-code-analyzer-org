package com.xssframework;

import com.xssframework.ui.AnalyzerGUI;

/**
 * Launcher for the Spring Boot Security Analyzer.
 * 
 * Usage:
 * java -cp ... com.xssframework.Launcher # Launch GUI
 * java -cp ... com.xssframework.Launcher gui # Launch GUI (explicit)
 * java -cp ... com.xssframework.Launcher cli <args> # Launch CLI
 */
public class Launcher {

    public static void main(String[] args) {
        if (args.length == 0) {
            // Default: launch GUI
            launchGUI();
        } else if (args[0].equalsIgnoreCase("gui")) {
            launchGUI();
        } else if (args[0].equalsIgnoreCase("cli")) {
            // Pass remaining args to Main
            String[] cliArgs = new String[args.length - 1];
            System.arraycopy(args, 1, cliArgs, 0, args.length - 1);
            Main.main(cliArgs);
        } else {
            // Treat as CLI arguments (project path)
            Main.main(args);
        }
    }

    private static void launchGUI() {
        javax.swing.SwingUtilities.invokeLater(() -> {
            AnalyzerGUI gui = new AnalyzerGUI();
            gui.setVisible(true);
        });
    }
}
