import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// 任务类
class Task implements Serializable {
    private String name;
    private String description;
    private boolean completed;

    public Task(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() { return name; }
    public String getDescription() { return description; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}

// 任务管理器类
class TaskManager implements Serializable {
    private List<Task> tasks = new ArrayList<>();

    public void addTask(Task task) {
        tasks.add(task);
    }

    public void saveTasks(String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(tasks);
            System.out.println("任务保存成功");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void loadTasks(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 漏洞点：直接反序列化不可信数据
            tasks = (List<Task>) ois.readObject();
            System.out.println("任务加载成功");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void displayTasks() {
        for (int i = 0; i < tasks.size(); i++) {
            Task task = tasks.get(i);
            System.out.println((i+1) + ". " + task.getName() + " - " + (task.isCompleted() ? "完成" : "未完成"));
        }
    }
}

// 恶意类示例（模拟攻击者构造的恶意序列化对象）
class MaliciousTask implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟攻击代码执行
        Runtime.getRuntime().exec("calc"); // Windows系统弹计算器
    }
}

public class TaskSystem {
    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\
1. 添加任务");
            System.out.println("2. 保存任务");
            System.out.println("3. 加载任务");
            System.out.println("4. 显示任务");
            System.out.println("5. 退出");
            System.out.print("选择操作: ");

            int choice = Integer.parseInt(scanner.nextLine());

            switch (choice) {
                case 1:
                    System.out.print("输入任务名称: ");
                    String name = scanner.nextLine();
                    System.out.print("输入任务描述: ");
                    String desc = scanner.nextLine();
                    manager.addTask(new Task(name, desc));
                    break;
                case 2:
                    manager.saveTasks("tasks.dat");
                    break;
                case 3:
                    manager.loadTasks("tasks.dat");
                    break;
                case 4:
                    manager.displayTasks();
                    break;
                case 5:
                    return;
            }
        }
    }
}