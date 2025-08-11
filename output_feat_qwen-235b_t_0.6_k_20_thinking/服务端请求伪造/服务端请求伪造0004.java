import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileDownloaderServlet extends HttpServlet {
    private static final String ALLOWED_PROTOCOL = "http";
    private static final String METADATA_SERVICE = "169.254.169.254";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String userInputUrl = request.getParameter("url");
        if (userInputUrl == null || userInputUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing URL parameter");
            return;
        }

        try {
            // Defective security check: only validates protocol prefix
            URL parsedUrl = new URL(userInputUrl);
            if (!parsedUrl.getProtocol().toLowerCase().startsWith(ALLOWED_PROTOCOL)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, 
                    "Invalid protocol. Only HTTP/HTTPS allowed");
                return;
            }

            // Vulnerable: No host validation allows internal network access
            HttpURLConnection connection = (HttpURLConnection) parsedUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            // Simulate file download processing
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                response.sendError(responseCode, "Failed to download file");
                return;
            }

            // Return only metadata to hide actual content
            response.setContentType("application/json");
            PrintWriter out = response.getWriter();
            out.println(String.format("{\\"status\\":\\"success\\",\\"contentLength\\":%d,\\"contentType\\":\\"%s\\"}",
                connection.getContentLength(),
                connection.getContentType()));

        } catch (MalformedURLException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL format");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Download failed");
        }
    }
}