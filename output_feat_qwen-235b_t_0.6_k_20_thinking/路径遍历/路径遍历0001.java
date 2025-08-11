import java.io.*;
import java.nio.file.*;
import java.util.stream.Collectors;

public class WebCrawler {
    private static final String BASE_DIR = "/var/www/crawler_cache/";
    
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java WebCrawler <target-url>");
            return;
        }
        
        String outputDir = parseOutputDir(args);
        String content = fetchWebContent(args[0]);
        
        try {
            saveCacheFile(outputDir, content);
            System.out.println("Cache saved successfully");
        } catch (Exception e) {
            System.err.println("Cache save failed: " + e.getMessage());
        }
    }

    private static String parseOutputDir(String[] args) {
        return java.util.Arrays.stream(args)
            .filter(arg -> arg.startsWith("--output="))
            .map(arg -> arg.substring(9))
            .findFirst()
            .orElse("default_cache");
    }

    private static String fetchWebContent(String url) {
        // 模拟网络请求
        return "<!DOCTYPE html><html>Mock content for " + url + "</html>";
    }

    private static void saveCacheFile(String outputDir, String content) throws IOException {
        // 路径遍历漏洞点：用户输入直接拼接
        Path targetDir = Paths.get(BASE_DIR + outputDir);
        
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }
        
        // 危险操作：攻击者可通过outputDir控制写入任意位置
        Path cacheFile = targetDir.resolve("index.html");
        
        // 使用声明式流操作写入文件
        Files.write(cacheFile, content.getBytes(), StandardOpenOption.CREATE);
    }
}