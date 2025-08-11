import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.Collectors;

public class DataCleanerService {
    private static final String CLEAN_DIR = "/var/data/clean/";
    private static final UnaryOperator<String> SANITIZER = s -> Arrays.stream(s.split(""))
        .map(c -> c.matches("[a-zA-Z0-9]") ? c : "_")
        .collect(Collectors.joining());

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java DataCleanerService <relativePath> <content>");
            return;
        }
        String relativePath = args[0];
        String content = args[1];
        DataCleanerService service = new DataCleanerService();
        try {
            service.cleanAndStore(relativePath, content);
            System.out.println("Data cleaned and stored successfully.");
        } catch (Exception e) {
            System.err.println("Error processing data: " + e.getMessage());
        }
    }

    public void cleanAndStore(String relativePath, String content) throws IOException {
        // 路径遍历漏洞点：用户输入直接拼接
        String fullPath = CLEAN_DIR + relativePath;
        try (FileWriter writer = new FileWriter(fullPath)) {
            writer.write(SANITIZER.apply(content));
        }
    }
}