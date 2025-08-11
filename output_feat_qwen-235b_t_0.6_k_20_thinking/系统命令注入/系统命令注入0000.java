import java.io.*;

public class FileEncryptionTool {
    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: java FileEncryptionTool <encrypt|decrypt> <inputFile> <outputFile> <password>");
            return;
        }

        String operation = args[0];
        String inputFile = args[1];
        String outputFile = args[2];
        String password = args[3];

        try {
            if (operation.equals("encrypt")) {
                encryptFile(inputFile, outputFile, password);
            } else if (operation.equals("decrypt")) {
                decryptFile(inputFile, outputFile, password);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            System.err.println("Error during file operation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String inputFile, String outputFile, String password) throws IOException, InterruptedException {
        String command = "openssl enc -aes-256-cbc -in " + inputFile + " -out " + outputFile + " -k " + password;
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        int exitCode = process.waitFor();
        if (exitCode == 0) {
            System.out.println("File encrypted successfully.");
        } else {
            System.err.println("Encryption failed with exit code " + exitCode);
        }
    }

    private static void decryptFile(String inputFile, String outputFile, String password) throws IOException, InterruptedException {
        String command = "openssl enc -d -aes-256-cbc -in " + inputFile + " -out " + outputFile + " -k " + password;
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        int exitCode = process.waitFor();
        if (exitCode == 0) {
            System.out.println("File decrypted successfully.");
        } else {
            System.err.println("Decryption failed with exit code " + exitCode);
        }
    }
}