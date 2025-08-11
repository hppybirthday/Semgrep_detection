import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class DataCleaner {
    public static void main(String[] args) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter filename to process (CSV only): ");
        
        try {
            String filename = reader.readLine();
            
            // Defense-style validation (flawed)
            if (!filename.endsWith(".csv")) {
                System.out.println("Invalid file type. Only CSV allowed.");
                return;
            }
            
            // Vulnerable command injection point
            String[] cmd = {"/bin/sh", "-c", "python3 /opt/data_processor.py '" + filename + "'"};
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Process process = pb.start();
            
            // Capture output
            BufferedReader outputReader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = outputReader.readLine()) != null) {
                System.out.println("Processed: " + line);
            }
            
        } catch (IOException e) {
            System.err.println("Error processing data: " + e.getMessage());
        }
    }
}