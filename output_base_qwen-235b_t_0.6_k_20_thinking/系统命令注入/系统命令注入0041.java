import java.io.*;
import java.util.*;

public class LogDataProcessor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter log filename to analyze:");
        String filename = scanner.nextLine();
        
        try {
            List<String> results = processLogFile(filename);
            System.out.println("Top 5 error patterns:");
            results.forEach(System.out::println);
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }

    private static List<String> processLogFile(String filename) throws IOException, InterruptedException {
        List<String> result = new ArrayList<>();
        
        // Simulate complex data processing pipeline
        String cmd = "grep 'ERROR' " + filename + " | sort | uniq -c | sort -nr | head -n 5";
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
        pb.redirectErrorStream(true);
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(pb.start().getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                result.add(line);
            }
        }
        
        return result;
    }
}
// Vulnerable when user input contains shell metacharacters
// Example payload: "; rm -rf / && echo 'compromised'"
// Compile: javac LogDataProcessor.java
// Run: java LogDataProcessor