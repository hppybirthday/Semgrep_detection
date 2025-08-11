import java.util.Scanner;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class ChatApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("欢迎使用聊天应用。输入 '!ping <host>' 测试连接，或 'exit' 退出。");

        Map<String, Consumer<String>> commands = new HashMap<>();

        commands.put("!ping", host -> {
            try {
                System.out.println("执行ping命令...");
                Process process = Runtime.getRuntime().exec("ping -c 4 " + host);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                System.err.println("执行命令失败: " + e.getMessage());
            }
        });

        commands.put("!exit", input -> {
            System.out.println("退出程序。");
            System.exit(0);
        });

        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) continue;

            String[] parts = input.split(" ", 2);
            String command = parts[0];
            String args = parts.length > 1 ? parts[1] : "";

            if (commands.containsKey(command)) {
                commands.get(command).accept(args);
            } else {
                System.out.println("未知命令: " + command);
            }
        }
    }
}