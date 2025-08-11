import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class VulnerableCrawler {
    public static void main(String[] args) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com"))
            .build();

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Document doc = Jsoup.parse(response.body());
            
            // 漏洞点：直接拼接原始HTML内容
            StringBuilder htmlOutput = new StringBuilder();
            htmlOutput.append("<html><body><h1>抓取内容：</h1><div>");
            htmlOutput.append(doc.select(".content").html());  // 未转义直接插入
            htmlOutput.append("</div></body></html>");
            
            // 生成包含XSS漏洞的HTML文件
            Files.write(Paths.get("output.html"), htmlOutput.toString().getBytes());
            System.out.println("生成成功");
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}

/*
Maven依赖配置：
<dependencies>
    <dependency>
        <groupId>org.jsoup</groupId>
        <artifactId>jsoup</artifactId>
        <version>1.14.3</version>
    </dependency>
</dependencies>
*/