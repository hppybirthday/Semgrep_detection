package com.bigdata.processor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

interface FileProcessor {
    List<String> processFile(String filename) throws IOException;
}

class LogFileProcessor implements FileProcessor {
    private static final String BASE_DIR = "/var/log/bigdata/";
    
    @Override
    public List<String> processFile(String filename) throws IOException {
        List<String> result = new ArrayList<>();
        Path filePath = Paths.get(BASE_DIR + filename);  // Vulnerable point
        
        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Process log data (simplified)
                result.add(line);
            }
        }
        return result;
    }
}

class DataProcessor {
    private FileProcessor processor;
    
    public DataProcessor(FileProcessor processor) {
        this.processor = processor;
    }
    
    public void analyzeLogs(String filename) {
        try {
            List<String> logs = processor.processFile(filename);
            System.out.println("Processed " + logs.size() + " log entries");
            // Additional analysis logic...
        } catch (IOException e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }
}

public class Main {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java Main <filename>");
            return;
        }
        
        FileProcessor processor = new LogFileProcessor();
        DataProcessor analyzer = new DataProcessor(processor);
        
        // Simulate processing of user-supplied filename
        analyzer.analyzeLogs(args[0]);
    }
}