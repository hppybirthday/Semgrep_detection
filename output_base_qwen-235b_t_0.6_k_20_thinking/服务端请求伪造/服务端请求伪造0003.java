import java.io.*;
import java.net.*;
import java.util.*;

class Task {
    private String name;
    private String callbackUrl;

    public Task(String name, String callbackUrl) {
        this.name = name;
        this.callbackUrl = callbackUrl;
    }

    public String getName() {
        return name;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }
}

class TaskService {
    private List<Task> tasks = new ArrayList<>();

    public void createTask(String name, String callbackUrl) {
        tasks.add(new Task(name, callbackUrl));
        System.out.println("[+] 任务创建成功: " + name);
    }

    public void completeTask(int index) {
        if (index >= tasks.size()) return;
        Task task = tasks.get(index);
        System.out.println("[>] 执行任务完成操作: " + task.getName());
        sendCompletionNotification(task.getCallbackUrl());
    }

    private void sendCompletionNotification(String url) {
        try {
            URL obj = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            String postData = "status=completed";
            OutputStream os = conn.getOutputStream();
            os.write(postData.getBytes());
            os.flush();
            
            System.out.println("[i] 已通知回调地址: " + url);
            System.out.println("[i] 响应代码: " + conn.getResponseCode());
            
        } catch (Exception e) {
            System.err.println("[!] 通知失败: " + e.getMessage());
        }
    }
}

public class TaskManager {
    public static void main(String[] args) {
        TaskService service = new TaskService();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 内部任务管理系统 ===");
        while (true) {
            System.out.print("\
1. 创建任务\
2. 完成任务\
选择操作: ");
            int choice = Integer.parseInt(scanner.nextLine());
            
            if (choice == 1) {
                System.out.print("输入任务名称: ");
                String name = scanner.nextLine();
                System.out.print("输入回调URL: ");
                String url = scanner.nextLine();
                service.createTask(name, url);
            } 
            else if (choice == 2) {
                System.out.print("输入任务索引: ");
                int index = Integer.parseInt(scanner.nextLine());
                service.completeTask(index);
            }
        }
    }
}