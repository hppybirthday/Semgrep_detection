import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// 任务类（存在反序列化漏洞的关键点）
class Task implements Serializable {
    private String name;
    private String command; // 恶意命令字段

    public Task(String name, String command) {
        this.name = name;
        this.command = command;
    }

    // 恶意代码执行点（反序列化时自动调用）
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            // 模拟攻击者注入的恶意代码
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            System.out.println("[!] 恶意命令执行失败");
        }
    }

    @Override
    public String toString() {
        return "任务名称: " + name;
    }
}

// 任务管理系统类
class TaskManager implements Serializable {
    private List<Task> tasks = new ArrayList<>();

    public void addTask(Task task) {
        tasks.add(task);
    }

    public void saveTasks(String filename) {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename))) {
            out.writeObject(tasks);
            System.out.println("[+] 任务保存成功");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void loadTasks(String filename) {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename))) {
            // 漏洞点：直接反序列化不可信数据
            tasks = (List<Task>) in.readObject();
            System.out.println("[+] 任务加载成功");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void listTasks() {
        System.out.println("=== 当前任务列表 ===");
        for (Task task : tasks) {
            System.out.println(task);
        }
    }
}

// 主程序
class TaskSystem {
    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\
任务管理系统");
            System.out.println("1. 添加任务");
            System.out.println("2. 保存任务");
            System.out.println("3. 加载任务");
            System.out.println("4. 列出任务");
            System.out.println("5. 退出");
            System.out.print("选择操作: ");

            int choice = Integer.parseInt(scanner.nextLine());

            switch (choice) {
                case 1:
                    System.out.print("输入任务名称: ");
                    String name = scanner.nextLine();
                    System.out.print("输入恶意命令（例如：calc）: ");
                    String command = scanner.nextLine();
                    manager.addTask(new Task(name, command));
                    break;
                case 2:
                    manager.saveTasks("tasks.dat");
                    break;
                case 3:
                    manager.loadTasks("tasks.dat");
                    break;
                case 4:
                    manager.listTasks();
                    break;
                case 5:
                    return;
            }
        }
    }
}