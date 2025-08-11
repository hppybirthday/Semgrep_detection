package com.example.mathsim;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 数学模型参数展示Servlet
 * 高抽象建模风格设计
 */
public class MathModelServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的模型参数（存在漏洞点）
        String modelName = request.getParameter("modelName");
        String initialCondition = request.getParameter("initialCondition");
        
        // 设置响应类型
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // 生成HTML响应（未转义用户输入）
        out.println("<html><head><title>Simulation Results</title></head><body>");
        out.println("<h1>Model: " + modelName + "</h1>");
        out.println("<p>Initial Condition: " + initialCondition + "</p>");
        
        // 模拟数学计算结果展示
        out.println("<div class='results'>");
        out.println("<h2>Simulation Output</h2>");
        out.println("<pre>\
" + 
            "Time | Value\
" + 
            "0.0  | 1.000\
" + 
            "1.0  | 2.718\
" + 
            "2.0  | 7.389\
" + 
            "</pre>");
        
        // 动态生成图表容器
        out.println("<div id='chart' data-model='" + modelName + "'>");
        out.println("<script src='/js/chart.js'></script>");
        out.println("</div>");
        
        // 添加用户评论区域（二次漏洞点）
        String userComment = request.getParameter("comment");
        if (userComment != null && !userComment.isEmpty()) {
            out.println("<div class='comment'>");
            out.println("<p>User Comment: " + userComment + "</p>");
            out.println("</div>");
        }
        
        // 添加模型描述（反射型XSS）
        String modelDesc = request.getParameter("desc");
        if (modelDesc != null) {
            out.println("<div class='description'>");
            out.println("<p>Model Description: " + modelDesc + "</p>");
            out.println("</div>");
        }
        
        out.println("</body></html>");
        out.close();
    }
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        // 显示初始表单
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<form method='post'>");
        out.println("Model Name: <input type='text' name='modelName'><br>");
        out.println("Initial Condition: <input type='text' name='initialCondition'><br>");
        out.println("Comment: <input type='text' name='comment'><br>");
        out.println("Description: <input type='text' name='desc'><br>");
        out.println("<input type='submit' value='Run Simulation'>");
        out.println("</form>");
        out.println("</body></html>");
        out.close();
    }
}