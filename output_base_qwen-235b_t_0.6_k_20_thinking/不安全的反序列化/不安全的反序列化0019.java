import java.io.*;
import java.util.ArrayList;
import java.util.List;

abstract class Task implements Serializable {
    private String taskId;
    private String description;
    
    public Task(String taskId, String description) {
        this.taskId = taskId;
        this.description = description;
    }
    
    public abstract void execute();
    
    @Override
    public String toString() {
        return "Task{id='" + taskId + "', desc='" + description + "'}";
    }
}

class ScheduledTask extends Task {
    private String schedule;
    
    public ScheduledTask(String id, String desc, String schedule) {
        super(id, desc);
        this.schedule = schedule;
    }
    
    @Override
    public void execute() {
        System.out.println("Executing scheduled task at " + schedule);
    }
}

// 恶意类通过反序列化触发代码执行
class MaliciousTask extends Task {
    public MaliciousTask() {
        super("malicious", "Exploit task");
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击载荷
        Runtime.getRuntime().exec("calc"); // 触发计算器作为攻击示例
    }
    
    @Override
    public void execute() {}
}

// 任务存储服务类
class TaskStorage implements Serializable {
    private List<Task> tasks = new ArrayList<>();
    
    public void addTask(Task task) {
        tasks.add(task);
    }
    
    public static void saveTasksToFile(String filename, TaskStorage storage) throws IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename))) {
            out.writeObject(storage);
        }
    }
    
    public static TaskStorage loadTasksFromFile(String filename) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename))) {
            return (TaskStorage) in.readObject(); // 不安全的反序列化
        }
    }
}

public class TaskManager {
    public static void main(String[] args) {
        try {
            // 创建任务存储
            TaskStorage storage = new TaskStorage();
            storage.addTask(new ScheduledTask("t1", "Daily backup", "0 2 * * *"));
            
            // 保存正常任务
            TaskStorage.saveTasksToFile("tasks.dat", storage);
            
            // 模拟加载用户数据（可能包含恶意内容）
            TaskStorage loaded = TaskStorage.loadTasksFromFile("tasks.dat");
            System.out.println("Loaded tasks: " + loaded.tasks.size());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}