import java.io.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class ChatApp {
    public static void main(String[] args) {
        Consumer<String> messageHandler = (msg) -> {
            if (msg.startsWith("/file")) {
                try {
                    String[] parts = msg.split(" ");
                    if (parts.length < 2) return;
                    
                    // 漏洞点：直接拼接用户输入到系统命令
                    String command = "cat " + parts[1];
                    Process process = Runtime.getRuntime().exec(command);
                    
                    // 读取命令输出
                    Stream.of(new BufferedReader(new InputStreamReader(
                        process.getInputStream())).lines())
                        .flatMap(stream -> stream)
                        .forEach(System.out::println);
                    
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };
        
        // 模拟用户输入
        String userInput = "/file ";
        System.out.println("输入消息（示例: /file test.txt）:");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            while ((userInput = reader.readLine()) != null) {
                messageHandler.accept(userInput);
                System.out.println("等待新消息...");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}