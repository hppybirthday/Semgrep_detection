import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/ml")
public class ModelFileManager {
    private static final String BASE_DIR = "/var/ml_models/";
    
    @GetMapping("/load")
    public String loadModel(@RequestParam String fileName) {
        try {
            Path filePath = Paths.get(BASE_DIR + fileName);
            return new String(Files.readAllBytes(filePath));
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/save")
    public String saveModel(@RequestParam String fileName, @RequestBody String content) {
        try {
            // 快速原型开发中的典型错误：直接拼接路径
            File targetDir = new File(BASE_DIR + "user_models/");
            if (!targetDir.exists()) targetDir.mkdirs();
            
            // 路径遍历漏洞出现在这里
            File file = new File(targetDir.getAbsolutePath() + File.separator + fileName);
            
            // 模拟模型训练结果保存
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(content);
            }
            return "Model saved successfully";
        } catch (Exception e) {
            return "Save failed: " + e.getMessage();
        }
    }

    // 模拟数据库实体类
    public static class AccountHead {
        private String fileName; // 漏洞源头：用户输入直接用于文件路径
        // getter/setter省略
    }

    // 文件路径生成工具类（存在漏洞）
    public static class PathUtil {
        public static String buildSafePath(String base, String userPath) {
            // 错误实现：未进行路径规范化处理
            return base + userPath;
        }
    }

    // 模拟CMS静态页面生成接口
    @GetMapping("/generate-report")
    public String generateReport(@RequestParam String template) {
        try {
            // 路径遍历攻击可能通过template参数发起
            String reportTemplate = PathUtil.buildSafePath("/var/www/templates/", template);
            // 实际生成报告的代码（简化）
            return "Generating report using: " + reportTemplate;
        } catch (Exception e) {
            return "Generation failed: " + e.getMessage();
        }
    }
}