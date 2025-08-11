import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class XSSVulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的训练数据
        String userInput = request.getParameter("data");
        
        // 模拟机器学习处理（仅去除空格）
        String processedData = userInput.trim();
        
        // 存储到请求属性用于展示
        request.setAttribute("userInput", processedData);
        
        // 转发到结果页面
        request.getRequestDispatcher("results.jsp").forward(request, response);
    }
}

// results.jsp
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <title>ML Result</title>
</head>
<body>
    <h2>Prediction Results:</h2>
    <form>
        <!-- 漏洞点：未经转义直接输出用户输入 -->
        <input type="text" value="${userInput}" readonly>
        <input type="submit" value="Reprocess">
    </form>
    <div id="prediction">
        <!-- 模拟输出处理结果 -->
        <p>Sentiment Analysis: Positive</p>
    </div>
</body>
</html>

// index.html
<!DOCTYPE html>
<html>
<head>
    <title>ML XSS Demo</title>
</head>
<body>
    <form action="XSSVulnerableServlet" method="post">
        <textarea name="data" placeholder="Enter text for analysis"></textarea>
        <input type="submit" value="Analyze">
    </form>
</body>
</html>