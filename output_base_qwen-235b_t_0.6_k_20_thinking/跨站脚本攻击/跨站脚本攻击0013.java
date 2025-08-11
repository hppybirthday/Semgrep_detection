import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// 数学模型基类
abstract class MathematicalModel {
    protected String name;
    public abstract String getDescription();
    
    public String getName() {
        return name;
    }
}

// 具体模型实现
class LinearModel extends MathematicalModel {
    public LinearModel(String name) {
        this.name = name;
    }
    
    @Override
    public String getDescription() {
        return "Linear model: y = mx + b";
    }
}

// 漏洞Servlet
public class XSSVulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的模型名称
        String modelName = request.getParameter("modelname");
        if (modelName == null || modelName.isEmpty()) {
            modelName = "DefaultModel";
        }
        
        // 创建数学模型
        MathematicalModel model = new LinearModel(modelName);
        
        // 设置响应类型
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // 漏洞点：直接将用户输入写入HTML响应
        out.println("<html><body>");
        out.println("<h1>Model Name: " + model.getName() + "</h1>");
        out.println("<p>Description: " + model.getDescription() + "</p>");
        out.println("<!-- User input is directly rendered without sanitization -->");
        out.println("<script>console.log('Model loaded at ' + new Date());</script>");
        out.println("</body></html>");
    }
}

/* 
Web.xml配置示例:
<servlet>
    <servlet-name>XSSVulnerableServlet</servlet-name>
    <servlet-class>XSSVulnerableServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>XSSVulnerableServlet</servlet-name>
    <url-pattern>/model</url-pattern>
</servlet-mapping>
*/