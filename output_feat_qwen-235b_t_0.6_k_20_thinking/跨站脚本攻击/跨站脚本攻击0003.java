import java.util.HashMap;
import java.util.Map;

class Task {
    private String id;
    private String title;
    private String faviconUrl;

    public Task(String id, String title, String faviconUrl) {
        this.id = id;
        this.title = title;
        this.faviconUrl = faviconUrl;
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public String getFaviconUrl() { return faviconUrl; }
}

class TaskRepository {
    private Map<String, Task> tasks = new HashMap<>();

    public void saveTask(Task task) {
        tasks.put(task.getId(), task);
    }

    public Task getTask(String id) {
        return tasks.get(id);
    }
}

class TaskView {
    public String renderTaskDetail(Task task) {
        StringBuilder html = new StringBuilder();
        html.append(String.format("<html><head><link rel='icon' href='%s'>", task.getFaviconUrl()));
        html.append(String.format("<title>%s</title></head><body>", task.getTitle()));
        html.append(String.format("<h1>%s</h1>", task.getTitle()));
        html.append("<a href='/tasks'>Back to list</a>");
        html.append("</body></html>");
        return html.toString();
    }
}

class TaskController {
    private TaskRepository repository = new TaskRepository();
    private TaskView view = new TaskView();

    public String createTask(String rawTitle, String rawFavicon) {
        String taskId = String.valueOf(System.currentTimeMillis());
        Task task = new Task(taskId, rawTitle, rawFavicon);
        repository.saveTask(task);
        return view.renderTaskDetail(task);
    }

    public String showTask(String taskId) {
        Task task = repository.getTask(taskId);
        if (task == null) return "Task not found";
        return view.renderTaskDetail(task);
    }
}

public class Main {
    public static void main(String[] args) {
        TaskController controller = new TaskController();
        
        // 恶意输入示例：包含javascript协议的favicon URL
        String maliciousFavicon = "javascript:alert(document.cookie='xss='+document.cookie)";
        
        // 创建任务（模拟用户提交请求）
        String htmlResponse = controller.createTask("XSS Demo Task", maliciousFavicon);
        
        System.out.println("--- 响应HTML内容 ---");
        System.out.println(htmlResponse);
    }
}