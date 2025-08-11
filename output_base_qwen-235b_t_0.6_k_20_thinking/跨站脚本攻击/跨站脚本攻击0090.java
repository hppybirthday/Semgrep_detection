import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.regex.*;

@WebServlet("/clean")
public class DataCleanerServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String name = request.getParameter("name");
        String comment = request.getParameter("comment");
        
        // 模拟数据清洗过程
        DataCleaner cleaner = new DataCleaner();
        String cleanedName = cleaner.sanitize(name);
        String cleanedComment = cleaner.sanitize(comment);
        
        // 将清洗后的数据显示在页面
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h2>清洗结果：</h2>");
        out.println("<p>姓名：" + cleanedName + "</p>");
        out.println("<p>评论：" + cleanedComment + "</p>");
        out.println("</body></html>");
    }
}

class DataCleaner {
    // 错误的数据清洗方法
    public String sanitize(String input) {
        if (input == null) return "";
        
        // 仅移除尖括号但保留内容
        String result = input.replaceAll("<", "&lt;");
        result = result.replaceAll(">", "&gt;");
        
        // 错误地重新插入可能的HTML标签
        result = result.replaceAll("&lt;script&gt;", "<script>");
        result = result.replaceAll("&lt;/script&gt;", "</script>");
        
        return result;
    }
}

/* web.xml配置
<servlet>
    <servlet-name>DataCleanerServlet</servlet-name>
    <servlet-class>DataCleanerServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>DataCleanerServlet</servlet-name>
    <url-pattern>/clean</url-pattern>
</servlet-mapping>
*/