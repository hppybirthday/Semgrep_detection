import java.io.*;
import java.util.Scanner;

public class MLDataProcessor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter dataset path for preprocessing:");
        String datasetPath = scanner.nextLine();
        
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", "python3 /scripts/preprocess.py " + datasetPath}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            reader.lines().forEach(System.out::println);
            int exitCode = process.waitFor();
            System.out.println("Preprocessing completed with exit code: " + exitCode);
            
        } catch (Exception e) {
            System.err.println("Error during preprocessing: " + e.getMessage());
        }
    }
}

/*
 * Vulnerable scenario:
 * 1. User input is directly concatenated into shell command
 * 2. Malicious input like "; rm -rf /" will execute additional commands
 * 3. Even with input validation attempts, improper sanitization remains
 * 4. ProcessBuilder alternative would be safer but still requires proper parameter handling
 */

// Sample vulnerable input handling
@FunctionalInterface
interface InputHandler {
    String processInput(String input);
}

class PathValidator implements InputHandler {
    @Override
    public String processInput(String input) {
        // Flawed validation that doesn't block malicious content
        return input.replaceAll("[^"]", ""); // Only blocks quotes
    }
}

// Actual vulnerability in command execution chain