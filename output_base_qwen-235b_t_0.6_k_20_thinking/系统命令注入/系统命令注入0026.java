import java.io.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to Data Cleaner v1.0");
        System.out.print("Enter input file path: ");
        String inputPath = scanner.nextLine();
        
        System.out.print("Enter output file path: ");
        String outputPath = scanner.nextLine();
        
        try {
            // Simulate data cleaning process using shell command
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", 
                "grep -v '^#' " + inputPath + " > " + outputPath);
            
            Process process = pb.start();
            int exitCode = process.waitFor();
            
            if (exitCode == 0) {
                System.out.println("Data cleaning completed successfully");
                System.out.println("Cleaned data saved to: " + outputPath);
                
                // Display first 5 lines of cleaned data
                ProcessBuilder viewPb = new ProcessBuilder("sh", "-c", 
                    "head -n 5 " + outputPath);
                Process viewProcess = viewPb.start();
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(viewProcess.getInputStream()));
                
                String line;
                System.out.println("\
First 5 lines of cleaned data:");
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } else {
                System.err.println("Data cleaning failed with exit code " + exitCode);
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}