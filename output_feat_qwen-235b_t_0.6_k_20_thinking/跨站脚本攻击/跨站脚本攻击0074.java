package com.example.vulnerableapp;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 模拟支付请求处理的数据清洗漏洞
 */
@WebServlet("/processPayment")
public class PaymentProcessor extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        // 模拟数据清洗流程
        String amount = request.getParameter("amount");
        String userId = request.getParameter("userId");
        
        // 不充分的数据清洗（防御式编程失败）
        if (amount == null || userId == null || !isValidAmount(amount) || !isValidUserId(userId)) {
            String errorMessage = "无效请求 - 用户输入: " + amount + " | 用户ID: " + userId;
            // 直接将用户输入拼接到HTML响应中，未进行HTML转义
            out.println("<div class='error'>" + errorMessage + "</div>");
            return;
        }
        
        // 正常处理逻辑（不会被执行）
        out.println("<div class='success'>支付处理成功</div>");
    }
    
    // 错误的验证方法（示例）
    private boolean isValidAmount(String amount) {
        // 不充分的验证逻辑
        return amount.matches("\\$?\\d+(\\.\\d{2})?"); // 允许美元符号和两位小数
    }
    
    // 错误的验证方法（示例）
    private boolean isValidUserId(String userId) {
        // 不充分的验证逻辑
        return userId.length() > 3 && userId.length() < 20;
    }
    
    @Override
    public void destroy() {
        // 清理资源
    }
}

/*
攻击示例:
POST /processPayment HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=<script>alert(document.cookie)</script>&userId=test

响应中将包含未转义的<script>标签，导致XSS攻击
*/