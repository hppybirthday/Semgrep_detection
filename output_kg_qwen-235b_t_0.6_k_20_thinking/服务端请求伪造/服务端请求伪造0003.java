import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

// 任务实体类
class Task {
    private String title;
    private String callbackUrl; // 存在风险的回调地址

    public Task(String title, String callbackUrl) {
        this.title = title;
        this.callbackUrl = callbackUrl;
    }

    public String getTitle() {
        return title;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }
}

// 任务服务类
class TaskService {
    // 模拟数据库存储
    private Map<String, Task> taskStore = new HashMap<>();

    // 创建任务并验证回调地址可用性
    public void createTask(Task task) throws IOException {
        taskStore.put(task.getTitle(), task);
        
        // 存在漏洞的URL访问
        URL url = new URL(task.getCallbackUrl());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.connect();
        
        // 读取响应内容（漏洞扩展点）
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        
        System.out.println("Callback response: " + response.toString());
    }
}

// 主程序入口
public class MainApplication {
    public static void main(String[] args) {
        TaskService taskService = new TaskService();
        
        // 模拟用户输入（攻击场景）
        String userInput = "http://localhost:8080/internal-api"; // 可被篡改的URL
        Task task = new Task("Test Task", userInput);
        
        try {
            taskService.createTask(task);
        } catch (IOException e) {
            System.err.println("Task creation failed: " + e.getMessage());
        }
    }
}