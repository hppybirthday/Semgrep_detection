import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

// 领域模型：爬虫任务
public class WebCrawler {
    private final String baseUrl;
    private final FileStorage fileStorage;

    public WebCrawler(String baseUrl, String storagePath) {
        this.baseUrl = baseUrl;
        this.fileStorage = new FileStorage(storagePath);
    }

    // 领域服务：执行爬取操作
    public void crawl(String relativeUrl, String outputSubPath) throws Exception {
        URL url = new URL(baseUrl + relativeUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) return;

        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.getInputStream()))) {
            
            String line;
            StringBuilder content = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            
            // 漏洞点：直接将用户输入路径传递给文件存储
            fileStorage.saveContent(outputSubPath, content.toString());
        }
    }

    // 基础设施：文件存储
    private static class FileStorage {
        private final String baseDirectory;

        FileStorage(String baseDirectory) {
            this.baseDirectory = baseDirectory;
        }

        // 存在路径遍历漏洞的方法
        void saveContent(String subPath, String content) throws IOException {
            // 危险的路径拼接操作
            File file = new File(baseDirectory + "/" + subPath);
            
            // 自动创建父目录（进一步扩大攻击面）
            file.getParentFile().mkdirs();
            
            try (BufferedWriter writer = new BufferedWriter(
                 new FileWriter(file))) {
                writer.write(content);
            }
        }
    }

    // 应用入口
    public static void main(String[] args) {
        try {
            // 示例参数：
            // 基础目录："/var/www/crawl_data"
            // 用户输入路径："../../../../tmp/evil.txt"
            WebCrawler crawler = new WebCrawler(
                "http://example.com", 
                "/var/www/crawl_data"
            );
            
            // 模拟攻击：通过路径遍历写入任意位置
            crawler.crawl("/index.html", "../../../../tmp/pwned.txt");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}