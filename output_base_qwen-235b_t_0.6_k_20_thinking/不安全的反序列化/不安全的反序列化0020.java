import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Base64;

public class UserPreferences implements Serializable {
    private String theme;
    private boolean notificationsEnabled;
    
    // Getters and setters
    public String getTheme() { return theme; }
    public void setTheme(String theme) { this.theme = theme; }
    public boolean isNotificationsEnabled() { return notificationsEnabled; }
    public void setNotificationsEnabled(boolean notificationsEnabled) { this.notificationsEnabled = notificationsEnabled; }
}

public class Exploit implements Serializable {
    private String command;
    
    public Exploit(String cmd) {
        this.command = cmd;
    }
    
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec(command);
    }
}

@WebServlet("/profile")
public class ProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        UserPreferences prefs = new UserPreferences();
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("user_prefs")) {
                    try {
                        // Vulnerable deserialization
                        String base64 = cookie.getValue();
                        byte[] data = Base64.getDecoder().decode(base64);
                        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                        Object obj = ois.readObject();
                        
                        if (obj instanceof UserPreferences) {
                            prefs = (UserPreferences) obj;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("Current Theme: " + prefs.getTheme() + "<br>");
        out.println("Notifications: " + (prefs.isNotificationsEnabled() ? "Enabled" : "Disabled"));
        out.println("</body></html>");
    }
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String theme = request.getParameter("theme");
        boolean notifications = "on".equals(request.getParameter("notifications"));
        
        UserPreferences prefs = new UserPreferences();
        prefs.setTheme(theme);
        prefs.setNotificationsEnabled(notifications);
        
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(prefs);
            oos.flush();
            String base64 = Base64.getEncoder().encodeToString(bos.toByteArray());
            
            Cookie cookie = new Cookie("user_prefs", base64);
            cookie.setMaxAge(60*60*24*30); // 30 days
            response.addCookie(cookie);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        response.sendRedirect("/profile");
    }
}