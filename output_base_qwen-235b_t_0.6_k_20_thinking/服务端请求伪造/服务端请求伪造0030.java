import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class AvatarDownloader extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String imageUrl = request.getParameter("url");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing URL parameter");
            return;
        }

        try {
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Failed to fetch image");
                return;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }

            reader.close();
            connection.disconnect();

            // Simulate saving image to local storage
            String localPath = "/var/www/images/" + System.currentTimeMillis() + "_avatar.jpg";
            try (FileWriter writer = new FileWriter(localPath)) {
                writer.write(content.toString());
            }

            response.setContentType("application/json");
            response.getWriter().write(String.format("{\\"status\\":\\"success\\",\\"path\\":\\"%s\\"}", localPath));

        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server error: " + e.getMessage());
        }
    }
}

/*
Deployment descriptor (web.xml):
<servlet>
    <servlet-name>AvatarDownloader</servlet-name>
    <servlet-class>AvatarDownloader</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>AvatarDownloader</servlet-name>
    <url-pattern>/downloadAvatar</url-pattern>
</servlet-mapping>
*/