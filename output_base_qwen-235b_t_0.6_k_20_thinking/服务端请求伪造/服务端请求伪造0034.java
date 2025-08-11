import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ChatImageHandler extends HttpServlet {
    private static final String ALLOWED_PROTOCOLS = "^(https?://).*";
    private static final String[] DANGEROUS_HEADERS = {"X-Forwarded-For", "Proxy-Connection"};

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String imageUrl = request.getParameter("imageUrl");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing image URL");
            return;
        }

        // Vulnerable: Only checks protocol but allows internal hosts
        if (!imageUrl.matches(ALLOWED_PROTOCOLS)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL scheme");
            return;
        }

        try {
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            // Defensive programming failure: Not sanitizing headers
            for (String header : DANGEROUS_HEADERS) {
                if (connection.getHeaderField(header) != null) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Forbidden header detected");
                    return;
                }
            }

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Failed to fetch image");
                return;
            }

            // Simulate image processing
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            StringBuilder imageContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                imageContent.append(line);
            }
            reader.close();

            // Store in chat message
            String safeContent = sanitizeImageContent(imageContent.toString());
            response.getWriter().write(String.format("<img src=\\"data:image/png;base64,%s\\">", safeContent));
            
        } catch (MalformedURLException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL format");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Image fetch failed");
        }
    }

    private String sanitizeImageContent(String content) {
        // Simplified sanitization (vulnerable to base64 bypass)
        return content.replaceAll("[\\\\r\\\
\\\\t]", "").trim();
    }
}