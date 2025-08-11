import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableServlet extends HttpServlet {
    static class User implements Serializable {
        String username;
        String role;
        private void readObject(ObjectInputStream in) {
            try {
                in.defaultReadObject();
                if("admin".equals(role)) {
                    Runtime.getRuntime().exec("calc");
                }
            } catch (Exception e) {}
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
            User user = (User)ois.readObject();
            req.getSession().setAttribute("user", user);
            res.getWriter().write("Welcome " + user.username);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        ServerSocket s = new ServerSocket(8080);
        while(true) {
            new Thread(() -> {
                try {
                    Socket socket = s.accept();
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream())
                    );
                    StringBuilder request = new StringBuilder();
                    String line;
                    while(!(line = reader.readLine()).isEmpty()) {
                        request.append(line).append("\
");
                    }
                    ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                    User user = new User();
                    user.username = "hacker";
                    user.role = "admin";
                    oos.writeObject(user);
                    oos.flush();
                } catch (Exception e) {}
            }).start();
        }
    }
}