import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.util.Base64;

// 快速原型开发的文件加密解密工具
public class FileCryptoServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
        throws ServletException, IOException {
        
        // 模拟身份认证：从rememberMe cookie获取用户信息
        Cookie[] cookies = req.getCookies();
        User user = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("rememberMe")) {
                    try {
                        // 存在漏洞的反序列化操作
                        String base64Data = cookie.getValue();
                        byte[] decoded = Base64.getDecoder().decode(base64Data);
                        user = JSON.parseObject(decoded, 0, decoded.length, 
                            Feature.SupportAutoType);
                        // user = FastJsonConvert.convertJSONToObject(decoded, User.class);
                        break;
                    } catch (Exception e) {
                        resp.sendError(400, "Invalid cookie format");
                        return;
                    }
                }
            }
        }

        if (user == null) {
            resp.sendError(401, "Authentication required");
            return;
        }

        // 文件处理逻辑（模拟）
        String action = req.getParameter("action");
        String filePath = req.getParameter("path");
        
        if ("encrypt".equals(action)) {
            // 模拟加密操作
            resp.getWriter().println("Encrypted file: " + filePath);
        } else if ("decrypt".equals(action)) {
            // 模拟解密操作
            resp.getWriter().println("Decrypted file: " + filePath);
        } else {
            resp.sendError(400, "Invalid action");
        }
    }
}

// User类定义
class User implements java.io.Serializable {
    private String username;
    private String role;
    
    public String getUsername() { return username; }
    public String getRole() { return role; }
    public void setUsername(String username) { this.username = username; }
    public void setRole(String role) { this.role = role; }
}

// FastJSON配置（模拟实际开发中的错误配置）
// 1. 启用了SupportAutoType功能
// 2. 未设置安全白名单
// 3. 未验证反序列化类型