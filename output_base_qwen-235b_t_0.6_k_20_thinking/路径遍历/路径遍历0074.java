import java.io.*;
import java.util.logging.*;

/**
 * 数据清洗服务 - 存在路径遍历漏洞
 */
public class DataCleanerServlet {
    private static final Logger logger = Logger.getLogger(DataCleanerServlet.class.getName());

    public String cleanData(String filePath) {
        try {
            // 模拟前端传递的文件路径参数
            String sanitizedPath = sanitizePath(filePath);
            
            // 危险：未完全验证的路径直接用于文件操作
            File file = new File("/var/data/uploads/" + sanitizedPath);
            
            if (!file.exists()) {
                logger.warning("文件不存在: " + filePath);
                return "错误：文件不存在";
            }
            
            // 记录被访问的绝对路径（漏洞暴露点）
            logger.info("访问文件绝对路径: " + file.getAbsolutePath());
            
            // 模拟数据清洗过程
            return processFileContent(file);
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "数据清洗失败", e);
            return "错误：处理文件时发生异常";
        }
    }

    private String sanitizePath(String path) {
        // 错误的防御：简单替换无法阻止编码绕过
        return path.replace("../", "").replace("..\\\\", "");
    }

    private String processFileContent(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 简单清洗：移除空行
                if (!line.trim().isEmpty()) {
                    content.append(line).append("\
");
                }
            }
        }
        return content.toString();
    }

    // 模拟测试入口
    public static void main(String[] args) {
        DataCleanerServlet cleaner = new DataCleanerServlet();
        
        // 正常用例
        System.out.println("正常测试:");
        System.out.println(cleaner.cleanData("valid_file.txt"));
        
        // 恶意用例（攻击面演示）
        System.out.println("\
恶意路径测试:");
        System.out.println(cleaner.cleanData(".../././etc/passwd"));
    }
}