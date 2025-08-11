import java.io.*;
import java.util.Base64;
import java.util.Date;

// 任务类（可序列化）
class Task implements Serializable {
    private String title;
    private String description;
    private Date dueDate;

    public Task(String title, String description, Date dueDate) {
        this.title = title;
        this.description = description;
        this.dueDate = dueDate;
    }

    @Override
    public String toString() {
        return "Task{title='" + title + "', description='" + description + "', dueDate=" + dueDate + "}";
    }
}

// 任务管理器类
class TaskManager {
    // 不安全的反序列化操作
    public static Task loadTask(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 漏洞点：直接反序列化不可信数据
            return (Task) ois.readObject();
        }
    }

    // 安全的序列化操作（对比演示）
    public static String saveTask(Task task) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(task);
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        }
    }
}

// 模拟Web控制器
class TaskController {
    // 模拟接收外部输入的接口
    public String handleTask(String encodedTask) {
        try {
            // 直接使用用户输入进行反序列化
            Task task = TaskManager.loadTask(encodedTask);
            return "Loaded task: " + task.toString();
        } catch (Exception e) {
            return "Error processing task: " + e.getMessage();
        }
    }
}

// 恶意代码执行类（演示攻击面）
// class MaliciousTask extends Task {
//     protected void finalize() {
//         try {
//             // 模拟执行任意代码（如启动计算器）
//             Runtime.getRuntime().exec("calc");
//         } catch (Exception ignored) {}
//     }
// }

// 主程序
class TaskSystem {
    public static void main(String[] args) throws Exception {
        // 正常使用示例
        Task originalTask = new Task("Sample Task", "Sample Description", new Date());
        String encoded = TaskManager.saveTask(originalTask);
        System.out.println("Serialized task: " + encoded);

        TaskController controller = new TaskController();
        System.out.println("Normal usage: " + controller.handleTask(encoded));

        // 漏洞演示（假设攻击者构造恶意输入）
        // String maliciousInput = generateMaliciousPayload();
        // System.out.println("Malicious attempt: " + controller.handleTask(maliciousInput));
    }
}