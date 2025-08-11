import java.io.*;
import java.util.function.*;
import java.util.*;

public class FileCryptoTool {
    static BiFunction<String, String, String> executeCommand = (cmd, input) -> {
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"bash", "-c", cmd + " " + input}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );
            
            StringBuilder output = new StringBuilder();
            reader.lines().forEach(output::append);
            errorReader.lines().forEach(output::append);
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    };

    static Consumer<String> encryptFile = filename -> {
        String password = "secure123"; // 模拟固定密码
        String command = String.format(
            "echo 'Encrypting %s' && openssl enc -aes-256-cbc -in %s -out %s.enc -pass pass:%s",
            filename, filename, filename, password
        );
        
        System.out.println(executeCommand.apply(command, ""));
    };

    static Consumer<String> decryptFile = filename -> {
        String password = "secure123"; // 与加密使用相同密码
        String command = String.format(
            "echo 'Decrypting %s' && openssl enc -d -aes-256-cbc -in %s -out %s.dec -pass pass:%s",
            filename, filename, filename, password
        );
        
        System.out.println(executeCommand.apply(command, ""));
    };

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java FileCryptoTool <encrypt|decrypt> <filename>");
            return;
        }

        String operation = args[0];
        String filename = args[1];

        switch (operation) {
            case "encrypt":
                encryptFile.accept(filename);
                break;
            case "decrypt":
                decryptFile.accept(filename);
                break;
            default:
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
        }
    }
}