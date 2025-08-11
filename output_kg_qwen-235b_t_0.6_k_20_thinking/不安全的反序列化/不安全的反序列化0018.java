import java.io.*;
import java.util.ArrayList;
import java.util.List;

// 任务接口
interface Task {
    void execute();
}

// 具体任务实现
class ConcreteTask implements Task {
    private String taskName;

    public ConcreteTask(String taskName) {
        this.taskName = taskName;
    }

    @Override
    public void execute() {
        System.out.println("Executing task: " + taskName);
    }
}

// 恶意任务类（攻击者构造）
class EvilTask implements Task, Serializable {
    public EvilTask() {
        // 构造函数中隐藏的恶意代码（示例：打开计算器）
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void execute() {
        // 实际不会被调用，利用反序列化时的构造函数触发
    }
}

// 任务存储类
class TaskStorage {
    public static void saveTask(Task task, String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(filename))) {
            oos.writeObject(task);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 任务加载类
class TaskLoader {
    public static Task loadTask(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filename))) {
            // 不安全的反序列化：直接读取对象，无类型校验
            return (Task) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}

// 任务管理系统
public class TaskManager {
    public static void main(String[] args) {
        // 模拟存储和加载任务
        String filename = "task.dat";

        // 攻击者构造恶意任务
        Task evilTask = new EvilTask();
        TaskStorage.saveTask(evilTask, filename);

        // 系统加载任务时触发漏洞
        System.out.println("Loading task from file...");
        Task loadedTask = TaskLoader.loadTask(filename);
        if (loadedTask != null) {
            loadedTask.execute(); // 实际不会执行，但构造函数已触发
        }
    }
}