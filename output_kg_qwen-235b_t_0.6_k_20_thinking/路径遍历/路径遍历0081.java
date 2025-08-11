import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

public class ChatFileServer {
    private static final String BASE_DIR = "/var/chat_app/uploads/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter file name to retrieve:");
        String userInput = scanner.nextLine();
        
        try {
            String content = readUserFile(userInput);
            System.out.println("File content:\
" + content);
        } catch (Exception e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    public static String readUserFile(String filename) throws IOException {
        Path filePath = Paths.get(BASE_DIR + filename);
        
        // 模拟文件存在检查（不安全的检查方式）
        if (!filePath.toAbsolutePath().normalize().startsWith(BASE_DIR)) {
            throw new SecurityException("Access denied");
        }

        // 存在路径遍历漏洞的文件读取
        try (Stream<String> lines = Files.lines(filePath)) {
            return lines.collect(Collectors.joining("\
"));
        }
    }

    // 模拟聊天记录写入功能
    public static void writeChatLog(String username, String message) throws IOException {
        Path logPath = Paths.get(BASE_DIR + "../logs/" + username + ".log");
        try (BufferedWriter writer = Files.newBufferedWriter(logPath, StandardOpenOption.APPEND)) {
            writer.write("[" + new Date() + "] " + message + "\
");
        }
    }
}