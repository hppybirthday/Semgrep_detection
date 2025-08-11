import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

// 模拟数据采集器
abstract class DataCollector {
    abstract String collectData(HttpServletRequest request);
}

// 用户输入采集器
class UserInputCollector extends DataCollector {
    @Override
    String collectData(HttpServletRequest request) {
        return request.getParameter("content"); // 直接获取原始用户输入
    }
}

// 数据处理器接口
interface DataProcessor {
    String processData(String rawData);
}

// 模拟大数据处理
class BigDataProcessor implements DataProcessor {
    @Override
    public String processData(String rawData) {
        // 模拟复杂处理流程
        return rawData.toUpperCase() + "_PROCESSED";
    }
}

// 报告生成器
class ReportGenerator {
    static String generateReport(String content) {
        // 漏洞点：未对内容进行HTML转义
        return "<html><body><h1>Report: " + content + "</h1></body></html>";
    }
}

// 恶意脚本注入示例
// 攻击载荷示例： <script>alert('xss')</script>

// 模拟的Servlet处理
public class XSSVulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        DataCollector collector = new UserInputCollector();
        DataProcessor processor = new BigDataProcessor();
        
        String rawData = collector.collectData(request);
        String processedData = processor.processData(rawData);
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(ReportGenerator.generateReport(processedData));
    }
}

/*
攻击流程示例：
1. 构造恶意请求：?content=<script>document.cookie='stolen='+document.cookie;</script>
2. 当其他用户查看该报告时，恶意脚本将在其浏览器上下文中执行
3. 可能导致会话cookie泄露、前端数据篡改等危害
*/