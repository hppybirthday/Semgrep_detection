import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptor <encrypt/decrypt> <inputFile> <outputFile>");
            return;
        }

        String operation = args[0];
        String inputPath = args[1];
        String outputPath = args[2];

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        try {
            ProcessBuilder processBuilder;
            if (operation.equalsIgnoreCase("encrypt")) {
                // Vulnerable command construction
                String cmd = String.format("openssl enc -e -aes-256-cbc -in %s -out %s -k %s",
                        inputPath, outputPath, password);
                processBuilder = new ProcessBuilder("bash", "-c", cmd);
            } else if (operation.equalsIgnoreCase("decrypt")) {
                // Vulnerable command construction
                String cmd = String.format("openssl enc -d -aes-256-cbc -in %s -out %s -k %s",
                        inputPath, outputPath, password);
                processBuilder = new ProcessBuilder("bash", "-c", cmd);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
                return;
            }

            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            
            if (exitCode == 0) {
                System.out.println(operation + " operation completed successfully");
            } else {
                System.err.println("Error during " + operation + " operation");
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
                String line;
                while ((line = errorReader.readLine()) != null) {
                    System.err.println(line);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}