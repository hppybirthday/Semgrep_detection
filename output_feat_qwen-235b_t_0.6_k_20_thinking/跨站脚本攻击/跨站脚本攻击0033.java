import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.jsoup.*;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

// 模拟爬虫控制器
public class VulnerableCrawlerServlet extends HttpServlet {
    private DataStorage storage = new DataStorage();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String targetUrl = request.getParameter("url");
        String category = request.getParameter("category");
        
        // 存储用户提交的恶意URL（未验证）
        storage.saveUserInput(targetUrl, category);
        
        // 抓取目标页面内容（反射型XSS载体）
        Document doc = Jsoup.connect(targetUrl).get();
        String pageTitle = doc.title();
        
        // 漏洞点：直接输出用户提交的URL参数
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>爬取结果 - " + category + "</h1>"); // 未转义category参数
        out.println("<p>目标页面标题: " + pageTitle + "</p>");
        out.println("<div>原始URL: " + targetUrl + "</div>"); // 直接输出用户输入
        out.println("</body></html>");
    }
}

// 数据存储类（模拟数据库）
class DataStorage {
    private Map<String, String> storedData = new HashMap<>();

    public void saveUserInput(String url, String category) {
        // 漏洞：未对输入内容进行HTML清理
        storedData.put(url, category);
    }

    public Map<String, String> getStoredData() {
        return storedData;
    }
}

// 管理界面Servlet
class AdminServlet extends HttpServlet {
    private DataStorage storage = new DataStorage();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body><h2>分类管理</h2>");
        
        // 漏洞：输出未经转义的存储数据
        for (Map.Entry<String, String> entry : storage.getStoredData().entrySet()) {
            out.println("<div>URL: " + entry.getKey() + " | 分类: " + entry.getValue() + "</div>");
        }
        
        out.println("</body></html>");
    }
}
// web.xml配置（模拟）
/*
<servlet>
    <servlet-name>Crawler</servlet-name>
    <servlet-class>VulnerableCrawlerServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>Crawler</servlet-name>
    <url-pattern>/crawl</url-pattern>
</servlet-mapping>
*/