import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatCommandServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        BufferedReader reader = request.getReader();
        StringBuilder json = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            json.append(line);
        }
        
        String message = extractValue(json.toString(), "message");
        if (message.startsWith("!exec")) {
            String cmd = message.substring(5).trim();
            executeCommand(cmd, response);
        } else {
            response.getWriter().write("{\\"status\\":\\"success\\"}");
        }
    }

    private String extractValue(String json, String key) {
        String target = "\\"" + key + "\\"";
        int start = json.indexOf(target) + target.length() + 2;
        int end = json.indexOf("\\"", start);
        return json.substring(start, end);
    }

    private void executeCommand(String cmd, HttpServletResponse response) {
        try {
            // 漏洞点：直接将用户输入拼接到命令数组中
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/bash", "-c", cmd});
            
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
            
            response.getWriter().write(
                "{\\"output\\":\\"" + output.toString().replace("\
", "\\\
") + "\\"}");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}