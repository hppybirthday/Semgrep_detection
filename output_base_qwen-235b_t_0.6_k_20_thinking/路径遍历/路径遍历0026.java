import java.io.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter log file name to process (e.g., app.log): ");
        String userInput = scanner.nextLine();
        
        // Base directory for log files
        File baseDir = new File("./data/logs/");
        
        // Vulnerable path construction
        File targetFile = new File(baseDir, userInput);
        
        if (!targetFile.exists()) {
            System.out.println("File not found: " + targetFile.getAbsolutePath());
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(targetFile))) {
            System.out.println("\
File content (cleaned format):\
----------------------");
            String line;
            while ((line = reader.readLine()) != null) {
                // Simple data cleaning: remove empty lines and trim whitespace
                String cleaned = line.trim();
                if (!cleaned.isEmpty()) {
                    System.out.println(cleaned);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Compilation command: javac DataCleaner.java
// Execution command: java DataCleaner