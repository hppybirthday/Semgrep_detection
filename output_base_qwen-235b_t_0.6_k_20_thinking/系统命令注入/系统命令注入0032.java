import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.function.Consumer;

public class FileEncryptor {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptor <operation> <file> <password>");
            System.out.println("Operation: encrypt | decrypt");
            return;
        }

        String operation = args[0];
        String filePath = args[1];
        String password = args[2];

        Consumer<String> executeCommand = cmd -> {
            try {
                Process process = Runtime.getRuntime().exec(cmd);
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
                
            } catch (IOException e) {
                e.printStackTrace();
            }
        };

        String command;
        if (operation.equalsIgnoreCase("encrypt")) {
            // Vulnerable command construction
            command = "openssl enc -e -aes-256-cbc -in " + filePath + 
                      " -out " + filePath + ".enc -k " + password;
            executeCommand.accept(command);
        } 
        else if (operation.equalsIgnoreCase("decrypt")) {
            // Vulnerable command construction
            command = "openssl enc -d -aes-256-cbc -in " + filePath + 
                      " -out " + filePath.replace(".enc", "") + 
                      " -k " + password;
            executeCommand.accept(command);
        }
        else {
            System.err.println("Invalid operation. Use 'encrypt' or 'decrypt'");
        }
    }
}