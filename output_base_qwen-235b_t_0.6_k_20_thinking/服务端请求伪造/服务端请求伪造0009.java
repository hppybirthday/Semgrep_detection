import java.io.*;
import java.net.*;
import java.util.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.util.*;

interface DataSource {
    String fetchData() throws Exception;
}

abstract class DataProcessor {
    protected DataSource dataSource;
    public DataProcessor(DataSource source) {
        this.dataSource = source;
    }
    public abstract String process();
}

class HttpDataSource implements DataSource {
    private String url;
    public HttpDataSource(String url) {
        this.url = url;
    }
    @Override
    public String fetchData() throws Exception {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);
        return EntityUtils.toString(client.execute(request).getEntity());
    }
}

class LocalFileSource implements DataSource {
    private String filePath;
    public LocalFileSource(String path) {
        this.filePath = path;
    }
    @Override
    public String fetchData() throws Exception {
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }
}

class Config {
    static String loadConfig(String key) {
        // 模拟从配置文件读取（实际可能包含用户输入）
        Map<String, String> configMap = new HashMap<>();
        configMap.put("data.url", "http://example.com/data");
        return configMap.getOrDefault(key, "default");
    }
}

public class BigDataPipeline {
    public static void main(String[] args) {
        try {
            // 漏洞点：直接使用未验证的配置值构造URL
            String dataSourceUrl = Config.loadConfig("data.url");
            if (dataSourceUrl.startsWith("file:")) {
                DataSource source = new LocalFileSource(dataSourceUrl.substring(5));
                DataProcessor processor = new DataProcessor(source) {
                    @Override
                    public String process() {
                        try {
                            return "Local data: " + dataSource.fetchData();
                        } catch (Exception e) { return "Error"; }
                    }
                };
                System.out.println(processor.process());
            } else {
                DataSource source = new HttpDataSource(dataSourceUrl);
                DataProcessor processor = new DataProcessor(source) {
                    @Override
                    public String process() {
                        try {
                            return "Remote data: " + dataSource.fetchData();
                        } catch (Exception e) { return "Error"; }
                    }
                };
                System.out.println(processor.process());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}