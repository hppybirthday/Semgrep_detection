import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ImageProxyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String imageUrl = request.getParameter("url");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing URL parameter");
            return;
        }
        
        try {
            // Vulnerable: Directly using user input to create URL
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            // Defense circumvention: Allow both HTTP and FILE protocols
            if (!url.getProtocol().startsWith("http") && !url.getProtocol().equals("file")) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Only HTTP/HTTPS/FILE allowed");
                return;
            }
            
            // Vulnerable: No validation for internal resources
            connection.connect();
            
            // Stream response
            response.setContentType("image/*");
            try (InputStream in = connection.getInputStream();
                 OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (MalformedURLException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL format");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error fetching image");
        }
    }
}