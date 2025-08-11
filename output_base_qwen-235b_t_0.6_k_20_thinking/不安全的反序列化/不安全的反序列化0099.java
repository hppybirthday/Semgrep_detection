import java.io.*;
import java.util.*;

interface Task extends Serializable {
    void execute();
}

class SimpleTask implements Task {
    private String command;
    
    public SimpleTask(String command) {
        this.command = command;
    }
    
    @Override
    public void execute() {
        try {
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class TaskService {
    private Map<String, Task> taskRegistry = new HashMap<>();
    
    public void registerTask(String name, Task task) {
        taskRegistry.put(name, task);
    }
    
    public void executeTask(String name) {
        Task task = taskRegistry.get(name);
        if (task != null) {
            task.execute();
        }
    }
    
    public void importTasks(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 漏洞点：直接反序列化不可信数据
            Map<String, Task> imported = (Map<String, Task>) ois.readObject();
            taskRegistry.putAll(imported);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public class TaskManager {
    public static void main(String[] args) {
        TaskService service = new TaskService();
        
        // 正常任务注册
        service.registerTask("list", () -> System.out.println("Listing tasks..."));
        
        // 模拟加载恶意任务文件
        if (args.length > 0) {
            service.importTasks(args[0]);
            service.executeTask("malicious");
        }
    }
}