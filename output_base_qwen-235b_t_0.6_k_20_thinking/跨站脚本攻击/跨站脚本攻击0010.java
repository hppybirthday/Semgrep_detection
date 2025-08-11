import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class CommentServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<form method='post'>");
        out.println("Comment: <input type='text' name='comment'><br>");
        out.println("<input type='submit' value='Submit'>");
        out.println("</form></body></html>");
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        String comment = request.getParameter("comment");
        
        // 漏洞点：不安全的数据清洗
        String cleaned = cleanData(comment);
        
        out.println("<html><body>");
        out.println("<h3>Submitted Comment:</h3>");
        out.println("<div style='border:1px solid;padding:10px;'>");
        out.println(cleaned);  // 直接输出未净化的内容
        out.println("</div></body></html>");
    }

    // 存在缺陷的数据清洗函数
    private String cleanData(String input) {
        // 错误的安全假设：仅移除显式<script>标签
        if (input == null) return "";
        
        // 危险的替换逻辑（不处理大小写/嵌套/编码绕过）
        String result = input.replace("<script>", "").replace("</script>", "");
        
        // 未处理其他潜在危险标签（如img/onerror）
        // 未进行HTML实体编码
        return result;
    }
}