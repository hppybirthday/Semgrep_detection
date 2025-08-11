package com.example.crawler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 领域实体
class Crawler {
    private String id;
    private String url;
    private String content;
    
    public Crawler(String id, String url, String content) {
        this.id = id;
        this.url = url;
        this.content = content;
    }
    
    public String getId() { return id; }
    public String getUrl() { return url; }
    public String getContent() { return content; }
}

// 仓储接口
interface CrawlerRepository {
    void save(Crawler crawler);
    List<Crawler> getAll();
}

// 内存实现
class InMemoryRepository implements CrawlerRepository {
    private List<Crawler> storage = new ArrayList<>();
    
    public void save(Crawler crawler) {
        storage.add(crawler);
    }
    
    public List<Crawler> getAll() {
        return new ArrayList<>(storage);
    }
}

// 应用服务
class CrawlerService {
    private CrawlerRepository repository;
    
    public CrawlerService(CrawlerRepository repository) {
        this.repository = repository;
    }
    
    public void processResult(String id, String url, String content) {
        repository.save(new Crawler(id, url, content));
    }
    
    public List<Crawler> getResults() {
        return repository.getAll();
    }
}

// Web控制器
@WebServlet("/crawl")
class CrawlerController extends HttpServlet {
    private CrawlerService service;
    
    public void init() {
        service = new CrawlerService(new InMemoryRepository());
    }
    
    protected void doGet(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        
        String url = req.getParameter("url");
        String content = "<!-- 模拟爬取结果 -->" + 
                      "<script>alert('xss');</script>";
        
        service.processResult("1", url, content);
        res.sendRedirect("results.jsp");
    }
}

// JSP页面（results.jsp）
// <html>
// <body>
// <h2>Results:</h2>
// <table>
// <c:forEach items="${results}" var="result">
// <tr>
// <td><input type="text" value="${result.content}"></td> <!-- 漏洞点 -->
// </tr>
// </c:forEach>
// </table>
// </body>
// </html>