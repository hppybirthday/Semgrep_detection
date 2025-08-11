import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class TaskManagerServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String keyword = request.getParameter("keyword");
        String htmlTemplate = "<html><body>\
"
            + "<h2>任务搜索结果</h2>\
"
            + "<div>搜索关键词: %s</div>\
"
            + "<div class='results'>\
"
            + "<p>暂无匹配任务</p>\
"
            + "</div>\
"
            + "<script>\
"
            + "function trackSearch() {\
"
            + "  var keyword = '%s';\
"
            + "  document.getElementById('analytics').value = keyword;\
"
            + "}\
"
            + "</script>\
"
            + "<input type='hidden' id='analytics'>\
"
            + "</body></html>";
            
        String safeKeyword = keyword != null ? keyword : "";
        out.printf(htmlTemplate, safeKeyword, safeKeyword);
    }
}

/*
任务管理系统抽象建模：
1. TaskEntity - 任务实体类
2. TaskService - 业务逻辑层
3. TaskController - 控制器层（由Servlet实现）
*/

abstract class TaskEntity {
    protected String title;
    protected String description;
    public abstract String getDisplayHtml();
}

class DefaultTask extends TaskEntity {
    public String getDisplayHtml() {
        return String.format("<div class='task'>%s</div>", title);
    }
}

interface TaskService {
    TaskEntity[] searchTasks(String keyword);
}

/*
XSS漏洞位置说明：
- 用户输入的keyword参数直接插入HTML文档流
- 在script标签中未经转义直接拼接字符串
- 恶意输入会被浏览器解析为JavaScript代码
*/