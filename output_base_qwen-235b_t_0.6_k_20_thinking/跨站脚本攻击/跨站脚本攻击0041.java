import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.util.stream.Collectors;

public class DataProcessorServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String keyword = request.getParameter("search");
        // 模拟大数据处理流程
        List<String> rawData = Arrays.asList("user_data1", "user_data2", "admin_data1");
        
        // 存在漏洞的声明式数据处理
        List<String> filteredData = rawData.stream()
            .filter(data -> data.contains(keyword))
            .collect(Collectors.toList());
            
        // 构造包含原始输入的响应
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>搜索结果 for: " + keyword + "</h2>");
        out.println("<ul>");
        filteredData.forEach(data -> out.println("<li>" + data + "</li>"));
        out.println("</ul>");
        // 模拟数据可视化组件
        out.println("<div id='chart'>可视化组件加载完成</div>");
        // 存在漏洞的JavaScript回调
        out.println("<script>");
        out.println("    document.getElementById('chart').innerHTML = '图表数据加载完成: " + keyword + "';");
        out.println("</script>");
        out.println("</body></html>");
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>DataProcessor</servlet-name>
    <servlet-class>DataProcessorServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>DataProcessor</servlet-name>
    <url-pattern>/process</url-pattern>
</servlet-mapping>
*/