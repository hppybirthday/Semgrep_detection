import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.net.*;
import java.nio.file.*;

public class ChatImageUploadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String imageUrl = request.getParameter("imageUrl");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing image URL");
            return;
        }

        try {
            // Vulnerable point: directly using user input to create URL
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Failed to fetch image");
                return;
            }

            // Save image locally
            Path tempFile = Files.createTempFile("chat_image_", ".jpg");
            try (InputStream in = connection.getInputStream();
                 OutputStream out = new FileOutputStream(tempFile.toFile())) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            // Process successful upload
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<h3>Image successfully uploaded and stored at: " + tempFile.toAbsolutePath() + "</h3>");
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing image: " + e.getMessage());
        }
    }

    // Simulate chat message handling
    private void processChatMessage(String message) {
        // Normal chat message processing logic
        System.out.println("Processing chat message: " + message);
    }

    // Simulate internal admin API (for demonstration purposes)
    private void internalAdminApiCall() {
        System.out.println("Executing internal admin API operation");
    }
}

// Web.xml configuration (simplified)
/*
<web-app>
    <servlet>
        <servlet-name>ChatImageUpload</servlet-name>
        <servlet-class>ChatImageUploadServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>ChatImageUpload</servlet-name>
        <url-pattern>/uploadImage</url-pattern>
    </servlet-mapping>
</web-app>
*/