import java.io.*;
import java.net.*;
import java.util.*;

// 模拟爬虫数据结构
interface PageProcessor {
    void process(byte[] rawData);
}

class DefaultSerializer implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject(); // 不安全的反序列化点
        }
    }
}

// 爬虫核心类
class CrawlerEngine {
    private PageProcessor processor;
    private final String targetUrl;

    public CrawlerEngine(String targetUrl) {
        this.targetUrl = targetUrl;
        this.processor = new PageDataProcessor();
    }

    public void startCrawling() throws Exception {
        byte[] rawData = fetchDataFromRemote();
        processor.process(rawData);
    }

    private byte[] fetchDataFromRemote() throws IOException {
        URL url = new URL(targetUrl);
        try (InputStream is = url.openStream()) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        }
    }
}

// 数据处理模块
class PageDataProcessor implements PageProcessor {
    @Override
    public void process(byte[] rawData) {
        try {
            Object obj = DefaultSerializer.deserialize(rawData);
            if (obj instanceof PageContent) {
                System.out.println("Processing content: " + ((PageContent) obj).getContent());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 可序列化数据结构
class PageContent implements Serializable {
    private static final long serialVersionUID = 2L;
    private String content;

    public PageContent(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

// 恶意类模拟攻击
// 示例攻击类（实际攻击中会隐藏在序列化数据中）
// class MaliciousPayload implements Serializable {
//     private static final long serialVersionUID = 3L;
//     private String cmd;
//     public MaliciousPayload(String cmd) { this.cmd = cmd; }
//     private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
//         Runtime.getRuntime().exec(cmd); // 执行任意命令
//     }
// }

// 主程序入口
public class VulnerableCrawler {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java VulnerableCrawler <url>");
            return;
        }
        
        CrawlerEngine engine = new CrawlerEngine(args[0]);
        engine.startCrawling();
    }
}