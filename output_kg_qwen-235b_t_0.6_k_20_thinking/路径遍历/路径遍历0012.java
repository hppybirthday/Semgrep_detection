import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * 数学模型文件管理器
 * 存在路径遍历漏洞的示例实现
 */
public class ModelFileManager {
    private static final String BASE_PATH = "/var/math_models/";

    /**
     * 加载模型文件
     * @param filename 用户指定的文件名
     * @return 文件内容
     * @throws IOException
     */
    public String loadModelFile(String filename) throws IOException {
        StringBuilder content = new StringBuilder();
        // 漏洞点：直接拼接用户输入
        String filePath = BASE_PATH + filename;
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    /**
     * 保存模型结果
     * @param filename 文件名
     * @param data 数据内容
     * @throws IOException
     */
    public void saveModelResult(String filename, String data) throws IOException {
        // 漏洞点：未验证文件路径
        String filePath = BASE_PATH + filename;
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(data);
        }
    }

    public static void main(String[] args) {
        ModelFileManager manager = new ModelFileManager();
        
        // 模拟用户输入（包含路径遍历攻击）
        String userInput = "../../../../etc/passwd";
        
        try {
            // 触发漏洞的文件读取
            String fileContent = manager.loadModelFile(userInput);
            System.out.println("文件内容：\
" + fileContent);
            
            // 漏洞利用示例：创建恶意文件
            manager.saveModelResult("malicious.txt", "恶意代码内容");
            
        } catch (IOException e) {
            System.err.println("操作失败：" + e.getMessage());
        }
    }
}

// 编译命令：javac ModelFileManager.java
// 运行命令：java ModelFileManager