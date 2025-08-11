import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * 极简数据清洗工具
 * 存在路径遍历漏洞
 */
public class DataCleaner {
    private static final String BASE_PATH = "/var/data/clean/";

    /**
     * 模拟清洗CSV文件
     * @param filename 用户输入的文件名
     * @throws IOException
     */
    public void cleanCSV(String filename) throws IOException {
        Path filePath = Paths.get(BASE_PATH + filename);
        
        // 模拟读取文件内容
        List<String> lines = Files.readAllLines(filePath);
        
        // 简单清洗操作：移除空行
        lines.removeIf(String::isEmpty);
        
        // 保存清洗后文件（漏洞点：未校验路径）
        Files.write(filePath, lines);
        
        // 清理临时文件（再次使用危险路径）
        deleteTempFile(filename);
    }

    /**
     * 删除临时文件
     * @param filename
     */
    private void deleteTempFile(String filename) {
        File tempFile = new File(BASE_PATH + "temp/" + filename);
        if(tempFile.exists()) {
            tempFile.delete();
        }
    }

    public static void main(String[] args) {
        DataCleaner cleaner = new DataCleaner();
        
        if(args.length == 0) {
            System.out.println("Usage: java DataCleaner <filename>");
            return;
        }
        
        try {
            cleaner.cleanCSV(args[0]);
            System.out.println("清洗完成");
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
        }
    }
}