import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.alibaba.fastjson.JSONObject;

@WebServlet("/account")
public class AccountServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        try {
            String conversationId = req.getParameter("conversationId");
            String metadata = req.getParameter("metadata");
            
            // 漏洞点：直接反序列化用户输入
            Account account = insertAccount(metadata);
            updateAccount(conversationId, metadata);
            
            resp.getWriter().write("Success");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Account insertAccount(String metadata) {
        // 危险的反序列化调用
        return JSONObject.parseObject(metadata, Account.class);
    }

    private void updateAccount(String conversationId, String metadata) {
        // 另一个反序列化入口点
        Account acc = JSONObject.parseObject(metadata, Account.class);
        // 模拟数据库更新操作
        System.out.println("Updating: " + conversationId);
    }
}

// 可序列化类
class Account implements java.io.Serializable {
    private String username;
    private transient String password; // 敏感字段
    
    // Getter/Setter
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}