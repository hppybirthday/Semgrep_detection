import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

/**
 * 大数据处理中的文件分析服务
 * 存在路径遍历漏洞
 */
public class DataAnalyzer {
    private static final Logger logger = Logger.getLogger(DataAnalyzer.class.getName());
    private final String dataRoot;

    public DataAnalyzer(String dataRoot) {
        this.dataRoot = dataRoot;
    }

    /**
     * 分析指定路径的数据文件
     * @param filePath 用户提交的相对路径
     * @return 文件内容摘要
     * @throws IOException
     */
    public String analyzeData(String filePath) throws IOException {
        // 漏洞点：直接拼接路径
        Path fullPath = Paths.get(dataRoot, filePath);
        
        if (!Files.exists(fullPath)) {
            throw new FileNotFoundException("数据文件不存在: " + filePath);
        }

        // 验证文件类型（不充分的防护）
        if (!filePath.endsWith(".csv") && !filePath.endsWith(".json")) {
            throw new SecurityException("不允许处理非数据文件");
        }

        // 模拟大数据处理
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = Files.newBufferedReader(fullPath)) {
            String line;
            int lineCount = 0;
            while ((line = reader.readLine()) != null && lineCount < 10) {
                content.append(line).append("\
");
                lineCount++;
            }
        }
        
        return String.format("文件摘要（%d行）:\
%s", lineCount, content.toString());
    }

    /**
     * 日志清理任务（定时执行）
     */
    public void cleanupLogs() {
        try {
            Files.walk(Paths.get(dataRoot, "logs"))
                .filter(path -> path.toString().endsWith(".log"))
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        logger.warning("清理日志失败: " + e.getMessage());
                    }
                });
        } catch (IOException e) {
            logger.severe("日志清理任务异常: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 模拟配置
        DataAnalyzer analyzer = new DataAnalyzer("/var/data/analytics");
        
        try {
            // 模拟用户输入
            String userInput = "../../../../../../etc/passwd";
            System.out.println("尝试分析文件: " + userInput);
            String result = analyzer.analyzeData(userInput);
            System.out.println("分析结果:\
" + result);
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
        }
    }
}