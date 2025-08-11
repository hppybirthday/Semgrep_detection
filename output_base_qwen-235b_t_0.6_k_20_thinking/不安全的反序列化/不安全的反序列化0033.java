import java.io.*;
import java.net.*;
import java.util.Base64;

// 网络爬虫任务类
class CrawlerTask implements Serializable {
    private String url;
    private transient String result;

    public CrawlerTask(String url) {
        this.url = url;
    }

    // 执行爬取操作
    public void execute() {
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "calc.exe");
            pb.start(); // 恶意代码执行点
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 响应处理器
class ResponseHandler {
    // 处理反序列化数据
    public void processResponse(String serializedData) {
        try {
            // 不安全的反序列化操作
            byte[] data = Base64.getDecoder().decode(serializedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            if (obj instanceof CrawlerTask) {
                ((CrawlerTask) obj).execute(); // 触发恶意代码执行
            }
        } catch (Exception e) {
            System.err.println("Deserialization error: " + e.getMessage());
        }
    }
}

// 网络爬虫主类
public class WebCrawler {
    private ResponseHandler responseHandler;

    public WebCrawler() {
        this.responseHandler = new ResponseHandler();
    }

    // 模拟网络请求
    public void fetch(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 从响应参数中提取序列化数据（错误的设计）
            String query = url.getQuery();
            if (query != null && query.startsWith("data=")) {
                String serializedData = query.substring(5);
                responseHandler.processResponse(serializedData);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            WebCrawler crawler = new WebCrawler();
            crawler.fetch(args[0]);
        } else {
            System.out.println("Usage: java WebCrawler <url>");
        }
    }
}