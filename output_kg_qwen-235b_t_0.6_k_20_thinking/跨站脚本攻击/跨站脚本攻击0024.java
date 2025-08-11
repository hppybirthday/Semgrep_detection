package com.example.bigdata;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/xss/vulnerable")
public class DataVisualizationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    // 模拟大数据存储
    private List<String> bigData = Arrays.asList(
        "Customer_A_2023_Q1",
        "Customer_B_2023_Q2",
        "Customer_C_2023_Q3"
    );

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的过滤条件（存在漏洞点）
        String filter = request.getParameter("filter");
        
        // 构建HTML响应
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        // 元编程风格：动态生成HTML模板
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>").append("\
");
        html.append("<html>").append("\
");
        html.append("<head>").append("\
");
        html.append("    <title>Big Data Report</title>").append("\
");
        html.append("</head>").append("\
");
        html.append("<body>").append("\
");
        html.append("    <h1>Data Filter: ").append(filter).append("</h1>").append("\
"); // 漏洞触发点
        html.append("    <table border='1'>").append("\
");
        html.append("        <tr><th>Filtered Data</th></tr>").append("\
");
        
        // 模拟大数据处理过程
        for (String data : bigData) {
            if (filter == null || data.contains(filter)) {
                html.append("        <tr><td>").append(data).append("</td></tr>").append("\
");
            }
        }
        
        html.append("    </table>").append("\
");
        html.append("    <script>").append("\
");
        html.append("        // Meta-programming feature: Dynamic script injection\
");
        html.append("        var filterValue = '").append(filter).append("';\
"); // 二次漏洞点
        html.append("        console.log('Current filter: ' + filterValue);");
        html.append("\
    </script>");
        html.append("\
</body>").append("\
");
        html.append("</html>");
        
        // 输出生成的HTML
        out.println(html.toString());
    }
}