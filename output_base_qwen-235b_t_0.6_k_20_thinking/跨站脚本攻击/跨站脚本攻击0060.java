import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

public class CustomerFeedbackServlet extends HttpServlet {
    private List<String> feedbackList = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String customerName = request.getParameter("customerName");
        String feedback = request.getParameter("feedback");
        
        // 直接存储用户输入到列表（未过滤特殊字符）
        feedbackList.add("<div class='feedback-item'><strong>" + customerName + ":</strong> " + feedback + "</div>");
        
        response.sendRedirect("feedback.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        request.setAttribute("feedbacks", feedbackList);
        RequestDispatcher dispatcher = request.getRequestDispatcher("feedback.jsp");
        dispatcher.forward(response, request);
    }
}

// feedback.jsp 内容：
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Customer Feedback</title></head>
<body>
    <h2>Customer Feedback</h2>
    <form method="post">
        Name: <input type="text" name="customerName"><br>
        Feedback: <input type="text" name="feedback"><br>
        <input type="submit" value="Submit">
    </form>
    <hr>
    <!-- 直接输出未净化的用户内容 -->
    <% for (String feedback : (List<String>)request.getAttribute("feedbacks")) { %>
        <%= feedback %>
    <% } %>
</body>
</html>