package com.example.vuln;

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * 不安全的反序列化示例
 * 开发者错误地认为输入数据来自可信内部系统，未验证反序列化内容
 */
public class UserServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(UserServlet.class.getName());

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try (InputStream is = request.getInputStream();
             ObjectInputStream ois = new ObjectInputStream(is)) {
            
            // 错误地反序列化用户输入，假设数据来自可信内部来源
            // 实际攻击者可以伪造请求体注入恶意序列化数据
            Object obj = ois.readObject();
            
            if (obj instanceof User) {
                User user = (User) obj;
                logger.log(Level.INFO, "Login attempt: {0}", user.getUsername());
                response.getWriter().write("<h1>Welcome " + user.getUsername() + "</h1>");
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data format");
            }
            
        } catch (Exception e) {
            // 防御式编程中的错误日志记录
            logger.log(Level.SEVERE, "Deserialization error: ", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

/**
 * 可序列化的用户类
 * 攻击者可能构造恶意子类注入执行代码
 */
class User implements Serializable {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    // 本应安全的反序列化钩子，但无法阻止恶意子类
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        if (username == null || password == null) {
            throw new InvalidObjectException("All fields must be non-null");
        }
    }
}