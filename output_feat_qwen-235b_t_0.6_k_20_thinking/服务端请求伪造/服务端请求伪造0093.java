import java.io.*;
import java.net.*;
import java.util.*;

// 主服务类
public class MathModelApp {
    public static void main(String[] args) {
        ImageProcessingService imageService = new ImageProcessingService();
        
        // 模拟用户输入（攻击者输入）
        String maliciousUri = "http://169.254.169.254/latest/meta-data/";
        System.out.println("[攻击示例] 尝试访问元数据服务...");
        
        try {
            imageService.generateThumbnail(maliciousUri);
        } catch (Exception e) {
            System.out.println("[攻击结果] 访问状态: " + e.getMessage());
        }
    }
}

// 图像处理服务类
class ImageProcessingService {
    private DataSourceChecker dataSourceChecker = new GenDatasourceConfServiceImpl();
    
    public void generateThumbnail(String imageUri) throws IOException {
        if (!dataSourceChecker.checkDataSource(imageUri)) {
            throw new IOException("无效的数据源");
        }
        // 实际生成缩略图的逻辑（此处简化）
        System.out.println("缩略图生成成功");
    }
}

// 数据源检查接口
interface DataSourceChecker {
    boolean checkDataSource(String uri) throws IOException;
}

// 漏洞实现类
class GenDatasourceConfServiceImpl implements DataSourceChecker {
    @Override
    public boolean checkDataSource(String uri) throws IOException {
        URL url = new URL(uri);
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            // 仅检查连接是否成功
            int responseCode = conn.getResponseCode();
            return (responseCode >= 200 && responseCode < 300);
            
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
}