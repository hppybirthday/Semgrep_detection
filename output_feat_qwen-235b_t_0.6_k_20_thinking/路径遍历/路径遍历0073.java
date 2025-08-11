import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;

/**
 * 大数据处理平台文件存储服务
 * 模拟HDFS本地映射存储的文件操作
 */
public class FileStorageService {
    private static final String BASE_PATH = "/var/data/warehouse/";
    private static final String TEMP_DIR = "/tmp/data_processing/";

    // 模拟文件上传处理
    public boolean processUpload(String bizPath, String fileName) {
        try {
            // 构造源文件路径（存在漏洞的路径拼接）
            File sourceFile = new File(TEMP_DIR + fileName);
            // 构造目标存储路径（危险的路径拼接）
            File targetFile = new File(BASE_PATH + bizPath + "/" + fileName);
            
            // 漏洞点：未校验bizPath中的路径遍历字符
            if (!sourceFile.exists()) {
                System.out.println("源文件不存在");
                return false;
            }
            
            // 使用Apache Commons IO进行文件移动
            FileUtils.moveFile(sourceFile, targetFile);
            System.out.println("文件迁移成功: " + targetFile.getAbsolutePath());
            return true;
            
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    // 模拟文件删除接口（第二个漏洞点）
    public boolean deleteFile(String basePath, String fileName) {
        // 危险的路径构造方式
        File targetFile = new File(basePath + "/" + fileName);
        
        // 漏洞分析：攻击者可构造basePath参数为../../etc/passwd
        boolean result = FileUtils.deleteQuietly(targetFile);
        System.out.println("文件删除 " + (result ? "成功" : "失败") + ": " + targetFile.getAbsolutePath());
        return result;
    }

    // 主程序模拟攻击场景
    public static void main(String[] args) {
        FileStorageService service = new FileStorageService();
        
        // 正常使用示例
        System.out.println("正常上传测试:");
        service.processUpload("user_data/2023", "test.csv");
        
        // 漏洞触发示例
        System.out.println("\
路径遍历漏洞测试（上传接口）:");
        // 攻击者可能构造的恶意路径
        service.processUpload("../../tmp/exploit", "malicious.sh");
        
        System.out.println("\
路径遍历漏洞测试（删除接口）:");
        // 漏洞利用：删除任意文件
        service.deleteFile("../../etc", "passwd");
    }
}