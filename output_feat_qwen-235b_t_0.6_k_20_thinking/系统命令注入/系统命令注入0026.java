import java.io.*;
import java.util.*;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter data file path:");
        String filepath = scanner.nextLine();
        
        // Simulate data cleaning process
        System.out.println("Starting data cleaning...");
        try {
            // Vulnerable command construction
            String cmd = "python /opt/data_cleaner/scripts/clean_data.py " + filepath;
            Process process = Runtime.getRuntime().exec(cmd);
            
            // Handle process output
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Output: " + line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                System.err.println("Error: " + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("Cleaning completed with exit code: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// CommandExecUtil (simplified example)
class CommandExecUtil {
    public static String execCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}