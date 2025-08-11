import java.io.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class TaskManagerApplication {

    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }

    @RestController
    @RequestMapping("/tasks")
    public class TaskController {

        @GetMapping("/download/{taskId}")
        public ResponseEntity<String> downloadTaskDetails(@PathVariable String taskId) {
            try {
                // 模拟任务数据存储路径
                String basePath = "data/";
                String filePath = basePath + taskId + ".txt";

                File file = new File(filePath);
                if (!file.exists()) {
                    return ResponseEntity.notFound().build();
                }

                StringBuilder content = new StringBuilder();
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\
");
                }
                reader.close();

                return ResponseEntity.ok(content.toString());
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Error: " + e.getMessage());
            }
        }
    }
}

// 项目结构要求：
// 1. 需要在项目根目录创建data文件夹
// 2. 存储任务文件示例：data/task001.txt
// 3. 攻击者可构造路径访问敏感文件