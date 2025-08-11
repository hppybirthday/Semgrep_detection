package com.example.ml;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 简单的机器学习预测服务（存在XSS漏洞）
 */
public class XSSVulnerableServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    // 模拟机器学习模型预测
    protected String predictSentiment(String text) {
        // 简单的规则模型（实际可能调用复杂模型）
        if (text.contains("happy") || text.contains("good")) {
            return "Positive";
        } else if (text.contains("sad") || text.contains("bad")) {
            return "Negative";
        }
        return "Neutral";
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        try {
            // 获取用户输入（未做任何验证）
            String userInput = request.getParameter("text");
            
            // 执行预测
            String prediction = predictSentiment(userInput);
            
            // 生成响应页面（直接拼接用户输入）
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head><title>Sentiment Analysis</title></head>");
            out.println("<body>");
            out.println("    <h1>Sentiment Prediction</h1>");
            out.println("    <p>Your input: " + userInput + "</p>");  // 漏洞点
            out.println("    <p>Prediction: " + prediction + "</p>");
            out.println("    <form method=\\"post\\">");
            out.println("        <textarea name=\\"text\\" rows=\\"4\\" cols=\\"50\\">Enter text here</textarea><br>");
            out.println("        <input type=\\"submit\\" value=\\"Analyze\\">");
            out.println("    </form>");
            out.println("</body>");
            out.println("</html>");
            
        } finally {
            out.close();
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doPost(request, response);
    }
}