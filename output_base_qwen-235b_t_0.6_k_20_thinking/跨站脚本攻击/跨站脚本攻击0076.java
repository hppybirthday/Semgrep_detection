import java.io.*;
import javax.servlet.*;
import javax.servlet.annotation.*;
import javax.servlet.http.*;

@WebServlet("/viewCustomer")
public class CustomerViewServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        String customerId = request.getParameter("id");
        
        // 模拟数据库查询
        String customerName = "John Doe";
        String contactInfo = "john@example.com";
        String notes = "";
        
        if (customerId != null && customerId.equals("123")) {
            notes = "<script>alert('XSS攻击成功!'+document.cookie)</script>";
        }
        
        try {
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>客户详情</title>");
            out.println("<link rel='stylesheet' href='/styles/main.css'>");
            out.println("</head>");
            out.println("<body>");
            out.println("<h1>客户信息</h1>");
            out.println("<table border='1'>");
            out.println("<tr><th>字段</th><th>值</th></tr>");
            out.println("<tr><td>客户ID</td><td>" + customerId + "</td></tr>");
            out.println("<tr><td>姓名</td><td>" + customerName + "</td></tr>");
            out.println("<tr><td>联系方式</td><td>" + contactInfo + "</td></tr>");
            out.println("<tr><td>备注</td><td>" + notes + "</td></tr>");
            out.println("</table>");
            out.println("<div id='analytics'>");
            out.println("<script src='/scripts/analytics.js'></script>");
            out.println("</div>");
            out.println("</body></html>");
        } finally {
            out.close();
        }
    }
}