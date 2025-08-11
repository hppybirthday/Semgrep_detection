import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// 模拟任务类
class Task implements Serializable {
    private String description;
    private boolean completed;

    public Task(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public void execute() {
        System.out.println("Executing task: " + description);
    }
}

// 任务管理器类
class TaskManager {
    private List<Task> tasks = new ArrayList<>();

    // 不安全的反序列化漏洞点
    public void loadTasksFromFile(String filename) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            tasks = (List<Task>) ois.readObject();
            System.out.println("Tasks loaded successfully");
        }
    }

    public void saveTasksToFile(String filename) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(tasks);
        }
    }

    public void addTask(Task task) {
        tasks.add(task);
    }

    public void listTasks() {
        for (int i = 0; i < tasks.size(); i++) {
            System.out.println((i + 1) + ". " + tasks.get(i).getDescription());
        }
    }
}

public class TaskSystem {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        TaskManager manager = new TaskManager();

        while (true) {
            System.out.println("\
Task Management System");
            System.out.println("1. Add Task");
            System.out.println("2. Save Tasks");
            System.out.println("3. Load Tasks");
            System.out.println("4. Exit");
            System.out.print("Choose option: ");

            int choice = Integer.parseInt(scanner.nextLine());

            try {
                switch (choice) {
                    case 1:
                        System.out.print("Enter task description: ");
                        String desc = scanner.nextLine();
                        manager.addTask(new Task(desc));
                        break;
                    case 2:
                        System.out.print("Enter filename to save: ");
                        String saveFile = scanner.nextLine();
                        manager.saveTasksToFile(saveFile);
                        break;
                    case 3:
                        System.out.print("Enter filename to load: ");
                        String loadFile = scanner.nextLine();
                        manager.loadTasksFromFile(loadFile);
                        break;
                    case 4:
                        System.out.println("Exiting...");
                        return;
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
    }
}