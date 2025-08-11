import java.io.*;
import java.util.Scanner;

// 任务管理系统核心类
public class TaskManager {
    private FileManager fileManager;

    public TaskManager() {
        this.fileManager = new FileManager("/var/task_system/");
    }

    // 加载任务文件
    public String loadTask(String filename) {
        return fileManager.readTaskFile(filename);
    }

    public static void main(String[] args) {
        TaskManager tm = new TaskManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 任务管理系统 ===");
        System.out.print("请输入任务文件名：");
        String filename = scanner.nextLine();
        
        String result = tm.loadTask(filename);
        System.out.println("文件内容：\
" + result);
    }
}

// 文件管理类
class FileManager {
    private String baseDirectory;

    public FileManager(String baseDir) {
        this.baseDirectory = baseDir;
    }

    // 存在漏洞的文件读取方法
    public String readTaskFile(String filename) {
        StringBuilder content = new StringBuilder();
        try {
            // 路径拼接漏洞点：未验证用户输入
            File file = new File(baseDirectory + filename);
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            reader.close();
        } catch (Exception e) {
            return "错误：" + e.getMessage();
        }
        return content.toString();
    }
}