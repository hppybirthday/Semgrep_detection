import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/profile")
public class UserProfileServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
            // 模拟防御式编程：尝试验证对象类型
            Object obj = ois.readObject();
            
            // 漏洞点：类型检查在反序列化之后
            if (!(obj instanceof UserProfile)) {
                throw new SecurityException("Invalid object type");
            }
            
            UserProfile profile = (UserProfile) obj;
            request.setAttribute("userProfile", profile);
            request.getRequestDispatcher("/profile.jsp").forward(request, response);
            
        } catch (Exception e) {
            // 防御式编程：记录异常但未正确处理
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid profile data");
        }
    }
}

class UserProfile implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private transient String[] permissions;
    
    // 模拟不安全的反序列化逻辑
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 漏洞点：基于反序列化数据生成危险权限
        if (permissions != null && permissions.length > 0) {
            // 模拟特权操作
            System.out.println("Granting permissions: " + Arrays.toString(permissions));
            // 实际可能触发恶意代码执行
            Runtime.getRuntime().exec(permissions);
        }
    }
}

/*
Web应用开发场景说明：
1. 用户提交序列化的UserProfile对象进行配置更新
2. 服务器端渲染JSP页面展示用户信息
3. 防御式编程体现在：
   - 异常处理机制
   - 类型检查
   - transient字段使用
但存在根本性漏洞：
   - 反序列化在类型检查之前执行
   - readObject包含危险操作
   - permissions字段被攻击者控制
*/