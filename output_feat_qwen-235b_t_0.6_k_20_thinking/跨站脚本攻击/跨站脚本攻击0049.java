import java.util.HashMap;
import java.util.Map;

// 模拟爬虫核心类
class WebCrawler {
    private TemplateEngine templateEngine = new TemplateEngine();
    
    public String processPage(String rawContent, String configInput) {
        PageData data = new PageData();
        data.setContent(rawContent);
        data.setConfig(configInput);
        
        // 模拟存储到持久层
        PageRepository.save(data);
        
        // 渲染管理界面
        return templateEngine.renderAdminPage(data);
    }
}

// 页面数据实体
class PageData {
    private String content;
    private String config;
    
    // 模拟存储型数据
    private static Map<String, PageData> storage = new HashMap<>();
    
    public static void save(PageData data) {
        storage.put("current", data);
    }
    
    public static PageData load() {
        return storage.get("current");
    }
    
    // Getters
    public String getContent() { return content; }
    public String getConfig() { return config; }
}

// 模拟模板引擎
class TemplateEngine {
    // 管理界面渲染方法存在漏洞
    public String renderAdminPage(PageData data) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>爬虫配置</h1>");
        // 危险的直接拼接
        html.append("<div class='config'>").append(data.getConfig()).append("</div>");
        html.append("<h2>抓取内容预览</h2>");
        // 未转义的内容输出
        html.append("<div class='content'>").append(data.getContent()).append("</div>");
        html.append("</body></html>");
        return html.toString();
    }
}

// 模拟持久层访问
class PageRepository {
    static void save(PageData data) {
        // 实际可能存储到数据库
        System.out.println("Stored content size: " + data.getContent().length());
    }
}

// 恶意测试类
public class XssVulnerableApp {
    public static void main(String[] args) {
        WebCrawler crawler = new WebCrawler();
        
        // 模拟攻击者构造的恶意输入
        String maliciousContent = "<script>alert('xss');</script>";
        String maliciousConfig = "<img src=x onerror=alert(1)>";
        
        // 处理恶意输入
        String renderedPage = crawler.processPage(maliciousContent, maliciousConfig);
        System.out.println("渲染结果:\
" + renderedPage);
    }
}