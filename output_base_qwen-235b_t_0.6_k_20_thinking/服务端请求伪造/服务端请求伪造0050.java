import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/share")
public class ChatImageShareServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String imageUrl = request.getParameter("url");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing image URL");
            return;
        }

        try {
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                String fileName = UUID.randomUUID() + ".jpg";
                String filePath = "/var/www/chat/images/" + fileName;
                
                try (InputStream in = connection.getInputStream();
                     FileOutputStream out = new FileOutputStream(filePath)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }

                response.setContentType("text/html");
                PrintWriter writer = response.getWriter();
                writer.println("<img src=\\"/images/" + fileName + "\\">" );
            } else {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                    "Failed to download image: " + connection.getResponseMessage());
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Error processing image: " + e.getMessage());
        }
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>ChatImageShareServlet</servlet-name>
    <servlet-class>ChatImageShareServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>ChatImageShareServlet</servlet-name>
    <url-pattern>/share</url-pattern>
</servlet-mapping>
*/