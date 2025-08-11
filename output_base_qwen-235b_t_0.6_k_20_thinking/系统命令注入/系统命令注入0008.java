import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class MLModelHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String modelPath = request.getParameter("model");
        String inputPath = request.getParameter("input");
        
        if(modelPath == null || inputPath == null) {
            response.sendError(400, "Missing parameters");
            return;
        }
        
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", 
                "python3 /ml/run_model.py --model " + modelPath + 
                " --input " + inputPath);
            
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
            
        } catch (Exception e) {
            response.sendError(500, "Internal server error");
        }
    }
}

// web.xml配置
/*
<web-app>
    <servlet>
        <servlet-name>MLHandler</servlet-name>
        <servlet-class>MLModelHandler</servlet-class>
    </servlet>
    <servlet-mapping>
        <url-pattern>/predict</url-pattern>
    </servlet-mapping>
</web-app>
*/