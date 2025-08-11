import java.io.*;
import java.net.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter file URL to download and encrypt:");
        String userInput = scanner.nextLine();
        
        try {
            String content = downloadFileFromURL(userInput);
            String encrypted = encryptContent(content);
            System.out.println("Encrypted content: " + encrypted);
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }

    private static String downloadFileFromURL(String urlString) throws IOException {
        StringBuilder content = new StringBuilder();
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        
        return content.toString();
    }

    private static String encryptContent(String content) {
        // 模拟加密操作
        return Base64.getEncoder().encodeToString(content.getBytes());
    }
}