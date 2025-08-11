import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

// 文件操作工具类
class FileUtil {
    static void writeStringToFile(String content, File file) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);
        }
    }

    static String readFileContent(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}

// 文件服务层
class FileService {
    private final File baseDirectory;

    FileService(String storagePath) {
        this.baseDirectory = new File(storagePath);
        if (!baseDirectory.exists()) {
            baseDirectory.mkdirs();
        }
    }

    void writeTaskFile(String relativePath, String content) throws IOException {
        File targetFile = new File(baseDirectory, relativePath);
        
        // 漏洞点：未校验路径遍历序列
        if (!targetFile.getCanonicalPath().startsWith(baseDirectory.getCanonicalPath())) {
            throw new SecurityException("Invalid path traversal attempt");
        }
        
        FileUtil.writeStringToFile(content, targetFile);
        System.out.println("File written to: " + targetFile.getAbsolutePath());
    }

    String readTaskFile(String relativePath) throws IOException {
        File targetFile = new File(baseDirectory, relativePath);
        return FileUtil.readFileContent(targetFile);
    }
}

// 任务管理层
class TaskManager {
    private final FileService fileService;

    TaskManager(FileService fileService) {
        this.fileService = fileService;
    }

    void processUserInput(String filePath, String content) {
        try {
            fileService.writeTaskFile(filePath, content);
            System.out.println("File operation completed");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

// 模拟入口类
public class TaskSystem {
    public static void main(String[] args) {
        FileService fileService = new FileService("/var/task_data");
        TaskManager taskManager = new TaskManager(fileService);
        
        // 模拟用户输入（漏洞触发点）
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter file path (e.g., reports/task1.txt): ");
        String filePath = scanner.nextLine();
        
        System.out.println("Enter file content: ");
        String content = scanner.nextLine();
        
        taskManager.processUserInput(filePath, content);
    }
}