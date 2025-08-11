import java.io.*;
import java.util.*;

interface TaskRepository {
    String getTaskDetails(String taskId);
}

class FileSystemTaskRepository implements TaskRepository {
    private final String storagePath;

    public FileSystemTaskRepository(String storagePath) {
        this.storagePath = storagePath;
    }

    @Override
    public String getTaskDetails(String taskId) {
        try {
            File file = new File(storagePath + File.separator + taskId + ".txt");
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            reader.close();
            return content.toString();
        } catch (Exception e) {
            return "Error reading task details";
        }
    }
}

class TaskService {
    private final TaskRepository repository;

    public TaskService(TaskRepository repository) {
        this.repository = repository;
    }

    public String exportTaskDetails(String taskId, String outputFileName) {
        String taskDetails = repository.getTaskDetails(taskId);
        try {
            // 漏洞点：直接拼接用户输入的文件名
            File outputFile = new File("exports/" + outputFileName);
            BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile));
            writer.write(taskDetails);
            writer.close();
            return "Export successful to: " + outputFile.getAbsolutePath();
        } catch (Exception e) {
            return "Export failed: " + e.getMessage();
        }
    }
}

public class TaskManagerApplication {
    public static void main(String[] args) {
        TaskRepository repo = new FileSystemTaskRepository("tasks_data");
        TaskService service = new TaskService(repo);
        
        // 模拟用户输入
        String taskId = "normal_task";
        // 恶意输入示例："../../malicious_output"
        String userInput = "../../malicious_output";
        
        String result = service.exportTaskDetails(taskId, userInput);
        System.out.println(result);
    }
}