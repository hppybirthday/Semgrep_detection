import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DatabaseBackupServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String filename = request.getParameter("filename");
        if (filename == null || filename.isEmpty()) {
            response.getWriter().write("Missing filename parameter");
            return;
        }

        try {
            // Vulnerable command construction: directly appending user input
            String[] cmd = {"/bin/sh", "-c", "mysqldump -u admin -p securepass mydb > /backups/" + filename};
            Process process = Runtime.getRuntime().exec(cmd);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            
            response.setContentType("text/plain");
            response.getWriter().write("Backup completed:\
" + output.toString());
            
        } catch (Exception e) {
            response.sendError(500, "Backup failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}