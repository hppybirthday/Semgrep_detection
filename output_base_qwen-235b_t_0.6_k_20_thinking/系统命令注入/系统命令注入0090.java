import java.io.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter filename to process:");
        String filename = scanner.nextLine();
        
        // Simulate data cleaning process using system command
        try {
            // Vulnerable command construction
            String cmd = "grep -v 'temp_data' " + filename + " > cleaned_data.tmp && mv cleaned_data.tmp " + filename;
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            // Handle command output
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            System.out.println("Processing output:");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            // Handle errors
            while ((line = errorReader.readLine()) != null) {
                System.err.println("Error: " + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("Cleanup complete with exit code: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}