import java.util.*;
import java.util.function.*;
import spark.*;
import static spark.Spark.*;

public class CrmApp {
    static List<Map<String, String>> customers = new ArrayList<>();

    public static void main(String[] args) {
        port(8080);
        
        // 客户搜索接口（存在XSS漏洞）
        get("/search", (req, res) -> {
            String query = req.queryParams("q");
            StringBuilder html = new StringBuilder();
            html.append("<html><body>");
            html.append("<h2>Search Results</h2>");
            html.append("<p>You searched for: ").append(query).append("</p>"); // 漏洞点：直接拼接用户输入
            html.append("<ul>");
            
            customers.stream()
                .filter(c -> c.get("name").contains(query))
                .forEach(c -> html.append("<li>").append(c.get("name")).append("</li>")); // 漏洞点：未转义输出
            
            html.append("</ul>");
            html.append("<a href='/'>Back</a>");
            html.append("</body></html>");
            return html.toString();
        });
        
        // 客户创建接口（存在XSS漏洞）
        post("/create", (req, res) -> {
            Map<String, String> customer = new HashMap<>();
            customer.put("name", req.queryParams("name")); // 直接存储用户输入
            customers.add(customer);
            res.redirect("/list");
            return "";
        });
        
        // 客户列表展示（存在XSS漏洞）
        get("/list", (req, res) -> {
            StringBuilder html = new StringBuilder();
            html.append("<html><body>");
            html.append("<h2>All Customers</h2>");
            html.append("<ul>");
            customers.forEach(c -> html.append("<li>").append(c.get("name")).append("</li>")); // 漏洞点：直接输出未过滤内容
            html.append("</ul>");
            html.append("<form action='/create' method='POST'>");
            html.append("New Customer: <input name='name'>");
            html.append("<button type='submit'>Add</button></form>");
            html.append("</body></html>");
            return html.toString();
        });
        
        // 首页
        get("/", (req, res) -> "<html><body><a href='/list'>View Customers</a><br><a href='/search?q=test'>Search</a></body></html>");
    }
}