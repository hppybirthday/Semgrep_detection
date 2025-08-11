import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Base64;

public class VulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String serializedUser = request.getParameter("user");
        if (serializedUser == null) {
            response.getWriter().write("<html><form method='post'><input name='user'><input type='submit'></form></html>");
            return;
        }

        try {
            byte[] data = Base64.getDecoder().decode(serializedUser);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            User user = (User) ois.readObject(); // 不安全的反序列化
            response.getWriter().write("Welcome, " + user.getName());
        } catch (Exception e) {
            response.getWriter().write("Deserialization error: " + e.getMessage());
        }
    }
}

class User implements Serializable {
    private String name;
    private transient String password; // 敏感字段

    public User(String name) {
        this.name = name;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟危险操作：执行命令（实际利用需要更复杂的gadget链）
        if (name.contains("|") || name.contains("&")) {
            try {
                Runtime.getRuntime().exec("calc"); // 模拟命令执行
            } catch (Exception ignored) {}
        }
    }

    public String getName() {
        return name;
    }
}