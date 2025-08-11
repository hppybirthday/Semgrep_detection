import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@WebServlet("/user/profile")
public class UserProfileServlet extends HttpServlet {
    private Map<String, String> userStore = new HashMap<>();

    @Override
    public void init() {
        userStore.put("default_user", "<b>Welcome</b>");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        String username = request.getParameter("user");
        String nickname = request.getParameter("nickname");
        
        if (username == null) username = "default_user";
        
        try {
            // 使用反射动态调用方法
            Method method = this.getClass().getMethod("renderProfile", 
                HttpServletRequest.class, PrintWriter.class, String.class);
            method.invoke(this, request, out, username);
            
        } catch (Exception e) {
            out.println("Error rendering profile");
        }
        
        // 元编程风格的恶意输入点
        if (nickname != null) {
            String template = "<div class='user-note'>%s</div>";
            // 漏洞：直接拼接用户输入
            out.printf(template, nickname);
        }
    }

    private void renderProfile(HttpServletRequest request, PrintWriter out, String username) {
        String userData = userStore.getOrDefault(username, "Guest");
        // 漏洞：未转义的动态输出
        out.println(String.format("<div class='profile'>%s</div>", userData));
        
        // 动态生成脚本标签
        String script = "<script>console.log('%s')</script>";
        out.println(String.format(script, request.getParameter("tracking")));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        String username = request.getParameter("user");
        String content = request.getParameter("content");
        
        if (username != null && content != null) {
            // 危险的动态代码执行
            userStore.put(username, "<div>" + content + "</div>");
            response.sendRedirect("/user/profile?user=" + username);
        }
    }
}