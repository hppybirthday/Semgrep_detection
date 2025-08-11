import java.io.*;
public class DataProcessor {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java DataProcessor <filename>");
            return;
        }
        try {
            processData(args[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void processData(String filename) throws IOException, InterruptedException {
        // Simulate ML data preprocessing pipeline
        System.out.println("[INFO] Starting data preprocessing...");
        
        // First validate file existence
        ProcessBuilder pb = new ProcessBuilder("python", "validate_file.py", filename);
        Process process = pb.start();
        process.waitFor();
        
        // Execute preprocessing script with user-controlled parameter
        // VULNERABLE: Direct concatenation of user input into command
        String[] cmd = {"/bin/bash", "-c", "python preprocess.py " + filename + " > /tmp/preprocessed_data.csv"};
        
        System.out.println("[DEBUG] Executing command: " + String.join(" ", cmd));
        
        ProcessBuilder vulnerablePb = new ProcessBuilder(cmd);
        Process vulnerableProcess = vulnerablePb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(vulnerableProcess.getInputStream()));
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(vulnerableProcess.getErrorStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        
        while ((line = errorReader.readLine()) != null) {
            System.err.println(line);
        }
        
        int exitCode = vulnerableProcess.waitFor();
        System.out.println("[INFO] Preprocessing completed with exit code " + exitCode);
    }
}