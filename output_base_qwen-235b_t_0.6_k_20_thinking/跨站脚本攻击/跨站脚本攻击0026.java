import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DataCleanerServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String rawData = request.getParameter("data");
        String cleanedData = cleanData(rawData);
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>清洗结果：</h2>");
        out.println("<div style='border:1px solid #ccc; padding:10px;'>");
        out.println(cleanedData);
        out.println("</div>");
        out.println("<br><a href='/'>返回</a>");
        out.println("</body></html>");
    }

    private String cleanData(String input) {
        // 初级数据清洗：移除<script>标签（不充分的防护）
        if (input == null) return "";
        
        // 错误的清洗逻辑：仅替换一次<script>标签
        String result = input.replaceFirst("(?i)<script>", "");
        result = result.replaceFirst("(?i)</script>", "");
        
        // 保留HTML格式的误判：允许部分标签
        return result;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>数据清洗服务</h2>");
        out.println("<form method='post'>");
        out.println("<textarea name='data' rows='10' cols='50'>请输入需要清洗的内容</textarea><br>");
        out.println("<input type='submit' value='清洗'>");
        out.println("</form>");
        out.println("</body></html>");
    }
}