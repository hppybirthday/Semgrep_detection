import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/category")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @PostMapping("/add")
    public String addCategory(@RequestParam String viewName, @RequestParam String suffix) {
        try {
            categoryService.saveViewTemplate(viewName, suffix);
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class CategoryService {
    private static final String BASE_PATH = "/var/www/html/views/";

    public void saveViewTemplate(String viewName, String suffix) throws IOException {
        String filePath = BASE_PATH + viewName + suffix;
        FileUtil.writeString(filePath, "<html>Template Content</html>");
    }
}

class FileUtil {
    public static void writeString(String path, String content) throws IOException {
        Path targetPath = Paths.get(path);
        // 模拟动态生成JSP文件的场景
        if (!Files.exists(targetPath.getParent())) {
            Files.createDirectories(targetPath.getParent());
        }
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(content.getBytes());
        }
    }
}

// Spring Boot启动类（简化）
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}