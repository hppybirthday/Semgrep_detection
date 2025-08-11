import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

// 任务实体类
class Task {
    private String taskId;
    private String imageUrl;

    public Task(String taskId, String imageUrl) {
        this.taskId = taskId;
        this.imageUrl = imageUrl;
    }

    public String getTaskId() { return taskId; }
    public String getImageUrl() { return imageUrl; }
}

// 存储服务模拟类
class StorageService {
    public void uploadImage(byte[] imageData, String filename) {
        System.out.println("[存储服务] 已上传文件: " + filename + " (大小: " + imageData.length + "字节)");
    }
}

// 管理服务层
public class AdminGoodsService {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final StorageService storageService = new StorageService();

    // 模拟下载任务图片的接口
    public void handleDownloadRequest(String taskId, String imageUrl) {
        Task task = new Task(taskId, imageUrl);
        try {
            downloadTaskImage(task);
        } catch (Exception e) {
            System.err.println("[错误] 下载失败: " + e.getMessage());
        }
    }

    // 存在漏洞的文件下载方法
    private void downloadTaskImage(Task task) throws Exception {
        String rawUrl = task.getImageUrl();
        
        // 危险操作：直接拼接用户输入的URL
        HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI(rawUrl))
            .GET()
            .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        
        // 响应处理：读取图片内容并上传（忽略失败情况）
        if (response.statusCode() == 200) {
            storageService.uploadImage(response.body(), "task_" + task.getTaskId() + "_image");
        } else {
            System.err.println("[警告] 非200响应: " + response.statusCode());
        }
    }

    // 模拟主方法
    public static void main(String[] args) {
        AdminGoodsService service = new AdminGoodsService();
        
        // 模拟正常请求
        System.out.println("--- 正常请求示例 ---");
        service.handleDownloadRequest("T001", "https://example.com/task_images/photo1.jpg");
        
        // 模拟SSRF攻击请求
        System.out.println("\
--- SSRF攻击示例 ---");
        service.handleDownloadRequest("T002", "file:///etc/passwd");
    }
}