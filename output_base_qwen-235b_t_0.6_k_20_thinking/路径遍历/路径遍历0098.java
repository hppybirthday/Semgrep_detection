import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/getChatHistory")
public class ChatHistoryServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String filename = request.getParameter("filename");
        if(filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        
        String basePath = "/var/chat/logs/";
        File file = new File(basePath + filename);
        
        if(!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        
        response.setContentType("text/plain");
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
        reader.close();
    }
}

// web.xml配置
<servlet>
    <servlet-name>ChatHistory</servlet-name>
    <servlet-class>ChatHistoryServlet</servlet-class>
</servlet>
<servlet-mapping>
    <url-pattern>/getChatHistory</url-pattern>
</servlet-mapping>