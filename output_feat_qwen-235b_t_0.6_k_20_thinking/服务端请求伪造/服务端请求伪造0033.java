import java.io.*;
import java.net.*;
import java.util.*;
import org.json.*;

// 模拟网络爬虫任务类
class CrawlerTask {
    private String baseUrl;
    private String logId;
    
    public CrawlerTask(String baseUrl, String logId) {
        this.baseUrl = baseUrl;
        this.logId = logId;
    }
    
    public JSONObject fetchContent() throws Exception {
        // 漏洞点：直接拼接URL参数
        String targetUrl = baseUrl + "?logId=" + logId;
        
        HttpURLConnection conn = (HttpURLConnection) new URL(targetUrl).openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        // 返回解析后的JSON响应
        return new JSONObject(response.toString());
    }
}

// 爬虫服务类
class CrawlerService {
    private List<CrawlerTask> tasks = new ArrayList<>();
    
    public void addTask(String baseUrl, String logId) {
        tasks.add(new CrawlerTask(baseUrl, logId));
    }
    
    public void processTasks() {
        for (CrawlerTask task : tasks) {
            try {
                JSONObject result = task.fetchContent();
                System.out.println("[+] Success: " + result.toString(2));
            } catch (Exception e) {
                System.err.println("[!] Error: " + e.getMessage());
            }
        }
    }
}

// 模拟日志处理服务
public class LogProcessingService {
    public static void main(String[] args) {
        // 内部服务地址（示例：云元数据服务）
        String internalEndpoint = "http://169.254.169.254/latest/meta-data/";
        
        // 模拟用户输入（攻击者控制logId参数）
        String maliciousLogId = "../../../../../etc/passwd%00"; // Null字节截断示例
        
        CrawlerService service = new CrawlerService();
        // 添加任务（漏洞触发点）
        service.addTask(internalEndpoint, maliciousLogId);
        
        // 执行爬虫任务
        service.processTasks();
    }
}