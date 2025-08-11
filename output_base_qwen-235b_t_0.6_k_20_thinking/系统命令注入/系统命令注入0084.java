import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileConverterServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String fileName = request.getParameter("filename");
        String outputFormat = request.getParameter("format");
        
        // 防御式编程：基本参数验证
        if (fileName == null || outputFormat == null || 
            !outputFormat.matches("[a-zA-Z0-9]+") || 
            !fileName.endsWith(".jpg")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameters");
            return;
        }
        
        try {
            // 漏洞点：危险的命令拼接
            String cmd = String.format("convert %s -resize 200x200 %s.%s", 
                fileName, fileName.substring(0, fileName.lastIndexOf('.')), outputFormat);
            
            // 执行系统命令
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<pre>Command output:\
" + output.toString() + "</pre>");
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}