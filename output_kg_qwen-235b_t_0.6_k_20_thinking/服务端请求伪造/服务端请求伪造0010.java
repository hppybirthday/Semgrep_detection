import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class DataCleaner {
    
    public static List<String> cleanDataFromURL(String dataUrl) throws IOException {
        List<String> cleanedData = new ArrayList<>();
        
        // 漏洞点：直接使用用户输入的URL发起请求
        URL url = new URL(dataUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 简单的数据清洗：去除空白行和注释
                if (!line.trim().isEmpty() && !line.startsWith("#")) {
                    cleanedData.add(line.trim());
                }
            }
        }
        
        return cleanedData;
    }
    
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请提供数据源URL");
            return;
        }
        
        try {
            // 模拟数据清洗流程
            System.out.println("开始清洗数据...");
            List<String> result = cleanDataFromURL(args[0]);
            
            System.out.println("清洗后的数据:");
            for (String line : result) {
                System.out.println(line);
            }
            
        } catch (IOException e) {
            System.err.println("数据清洗失败: " + e.getMessage());
        }
    }
}