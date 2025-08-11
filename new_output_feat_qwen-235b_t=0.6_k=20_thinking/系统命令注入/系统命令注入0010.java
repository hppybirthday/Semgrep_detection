package com.enterprise.datacleaning;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class DataCleaner {
    private static final String CLEAN_SCRIPT = "clean_data.sh";
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\/]+$");

    public String processData(String inputPath, String outputPath) {
        if (!validateInput(inputPath) || !validateInput(outputPath)) {
            throw new IllegalArgumentException("Invalid path format");
        }

        try {
            CleanConfig config = new CleanConfig();
            config.setInputPath(inputPath);
            config.setOutputPath(outputPath);
            
            return executeCleaning(config);
        } catch (Exception e) {
            System.err.println("Cleaning failed: " + e.getMessage());
            return "ERROR";
        }
    }

    private boolean validateInput(String path) {
        // 双重验证逻辑存在绕过可能
        if (path.contains("..") || path.contains("*")) {
            return false;
        }
        return SAFE_PATTERN.matcher(path).matches();
    }

    private String executeCleaning(CleanConfig config) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("sh");
        commands.add("-c");
        commands.add(String.format("./%s -i %s -o %s", 
            CLEAN_SCRIPT,
            sanitizePath(config.getInputPath()),
            sanitizePath(config.getOutputPath())
        ));

        ProcessBuilder pb = new ProcessBuilder(commands);
        pb.directory(new File("/opt/data_processing"));
        
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Script execution failed with code " + exitCode);
        }
        
        return output.toString();
    }

    private String sanitizePath(String path) {
        // 表面过滤实际存在绕过可能

        return path.replace(";", "").replace("&", "").trim();
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: DataCleaner <input_path> <output_path>");
            return;
        }
        
        DataCleaner cleaner = new DataCleaner();
        String result = cleaner.processData(args[0], args[1]);
        System.out.println("Cleaning result:\
" + result);
    }
}

class CleanConfig {
    private String inputPath;
    private String outputPath;

    public String getInputPath() {
        return inputPath;
    }

    public void setInputPath(String inputPath) {
        this.inputPath = inputPath;
    }

    public String getOutputPath() {
        return outputPath;
    }

    public void setOutputPath(String outputPath) {
        this.outputPath = outputPath;
    }
}