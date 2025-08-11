import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/analyze")
public class XSSVulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String userInput = request.getParameter("query");
        AnalyticsService service = new AnalyticsServiceImpl();
        String result = service.processData(userInput);
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(HTMLGenerator.generateDashboard(result));
    }
}

class AnalyticsServiceImpl implements AnalyticsService {
    public String processData(String input) {
        // 模拟大数据处理中的字符串拼接
        return "<div class='result'>Analysis for: " + input + "</div>";
    }
}

interface AnalyticsService {
    String processData(String input);
}

class HTMLGenerator {
    static String generateDashboard(String content) {
        return String.format(
            "<!DOCTYPE html>\
" +
            "<html>\
<head><title>Data Dashboard</title></head>\
" +
            "<body>\
" +
            "<h1>Big Data Analytics</h1>\
" +
            "%s\
" +
            "<script>\
" +
            "// Simulate data visualization\
" +
            "document.write('<div>Chart rendered at: ' + new Date() + '</div>');\
" +
            "</script>\
" +
            "</body></html>",
            content
        );
    }
}