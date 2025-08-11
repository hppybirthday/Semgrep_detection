import java.io.*;
import java.util.function.*;
import java.util.stream.Collectors;

public class LogDataCleaner {
    public static void main(String[] args) {
        Function<String, String> buildCommand = input -> 
            "grep -v 'sensitive' " + input + " | wc -l"; // Vulnerable command construction

        try {
            System.out.println("Enter log filename to process:");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in)
            );
            
            String userInput = reader.readLine();
            
            // Vulnerable command execution chain
            ProcessBuilder pb = new ProcessBuilder(
                "bash", "-c", buildCommand.apply(userInput)
            );
            
            Process process = pb.start();
            
            // Process output (simplified for demo)
            String output = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            ).lines().collect(Collectors.joining("\
"));
            
            String error = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            ).lines().collect(Collectors.joining("\
"));
            
            int exitCode = process.waitFor();
            
            System.out.println("\
Execution Result:");
            System.out.println("Exit Code: " + exitCode);
            System.out.println("Output: " + output);
            System.out.println("Error: " + error);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}