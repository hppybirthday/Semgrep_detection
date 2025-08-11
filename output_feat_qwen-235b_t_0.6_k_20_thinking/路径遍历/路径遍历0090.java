import java.io.*;
import java.util.*;

// 文件路径生成工具类
public class FilePathUtil {
    public static String buildFilePath(String basePath, String categoryLink) {
        return basePath + File.separator + categoryLink;
    }
}

// 数据清洗服务类
class DataCleaner {
    private static final String BASE_PATH = "/var/data/clean/";
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(Arrays.asList(".log", ".tmp"));

    public void batchDeleteFiles(String prefix, String suffix) throws IOException {
        // 漏洞点：直接拼接用户输入
        String targetPath = FilePathUtil.buildFilePath(BASE_PATH, prefix + "*" + suffix);
        File dir = new File(BASE_PATH);
        
        if (!dir.exists() || !dir.isDirectory()) {
            throw new IllegalArgumentException("Invalid base directory");
        }

        // 模拟数据清洗操作
        for (File file : Objects.requireNonNull(dir.listFiles())) {
            if (file.getName().startsWith(prefix) && file.getName().endsWith(suffix)) {
                System.out.println("Deleting file: " + file.getAbsolutePath());
                file.delete();
            }
        }

        // 危险操作：任意文件覆盖
        File targetFile = new File(targetPath);
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write("[CLEANED DATA]".getBytes());
        }
    }
}

// 模拟API接口
class FileCleanController {
    public static void main(String[] args) {
        try {
            DataCleaner cleaner = new DataCleaner();
            // 模拟攻击参数：prefix=../../etc/passwd&suffix=
            String prefix = args.length > 0 ? args[0] : "normal_prefix";
            String suffix = args.length > 1 ? args[1] : "normal_suffix";
            
            cleaner.batchDeleteFiles(prefix, suffix);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}