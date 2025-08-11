package com.example.xss;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/clean")
public class CleanServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static List<String> cleanedContents = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String content = request.getParameter("content");
        
        // 模拟数据清洗逻辑：替换空格为下划线（不充分的安全处理）
        String cleanedContent = content.replace(" ", "_");
        
        // 存储历史记录
        cleanedContents.add(cleanedContent);
        
        // 直接传递未转义内容
        request.setAttribute("cleanedContent", cleanedContent);
        request.setAttribute("history", cleanedContents);
        request.getRequestDispatcher("/result.jsp").forward(request, response);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.setAttribute("history", cleanedContents);
        response.getWriter().append(
            "<html><body>" +
            "<h3>数据清洗工具</h3>" +
            "<form method='post' action='clean'>" +
            "输入内容：<br>" +
            "<textarea name='content' rows='10' cols='30'></textarea><br>" +
            "<input type='submit' value='清洗'>" +
            "</form>" +
            "<h4>历史记录：</h4><ul>" +
            (cleanedContents.isEmpty() ? "<li>暂无记录</li>" : "") +
            "</ul></body></html>"
        );
    }
}

// result.jsp（需放在webapp目录下）
// <html><body>
// <h3>清洗后的内容：</h3>
// <div>${cleanedContent}</div>
// <h4>历史记录：</h4>
// <ul>
//     <% List<String> history = (List<String>) request.getAttribute("history"); 
//        for (String item : history) {
//            out.println("<li>" + item + "</li>");
//        } %>
// </ul>
// </body></html>