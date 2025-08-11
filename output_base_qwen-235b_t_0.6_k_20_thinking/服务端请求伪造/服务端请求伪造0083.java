import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

// 任务实体类
class Task {
    private String id;
    private String description;
    private String sourceUrl; // 存在风险的字段

    public Task(String id, String description, String sourceUrl) {
        this.id = id;
        this.description = description;
        this.sourceUrl = sourceUrl;
    }

    public String getId() { return id; }
    public String getDescription() { return description; }
    public String getSourceUrl() { return sourceUrl; }
}

// 任务处理服务
class TaskService {
    // 模拟数据库
    private Map<String, Task> taskStore = new HashMap<>();

    public void createTask(Task task) throws IOException {
        // 危险的操作：直接使用用户提供的URL
        if (task.getSourceUrl() != null && !task.getSourceUrl().isEmpty()) {
            String content = fetchRemoteContent(task.getSourceUrl());
            System.out.println("[系统提示] 已自动导入外部内容: " + content.substring(0, Math.min(50, content.length())) + "...");
        }
        
        taskStore.put(task.getId(), task);
        System.out.println("任务 " + task.getId() + " 已创建");
    }

    // 存在漏洞的URL访问方法
    private String fetchRemoteContent(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        
        return content.toString();
    }
}

// 模拟应用入口
public class TaskManagementSystem {
    public static void main(String[] args) {
        TaskService taskService = new TaskService();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 任务管理系统（存在SSRF漏洞）===");
        System.out.print("输入任务ID: ");
        String id = scanner.nextLine();
        
        System.out.print("输入任务描述: ");
        String description = scanner.nextLine();
        
        System.out.print("输入外部数据源URL（可选）: ");
        String sourceUrl = scanner.nextLine();
        
        try {
            Task task = new Task(id, description, sourceUrl);
            taskService.createTask(task);
        } catch (Exception e) {
            System.err.println("创建任务失败: " + e.getMessage());
        }
    }
}