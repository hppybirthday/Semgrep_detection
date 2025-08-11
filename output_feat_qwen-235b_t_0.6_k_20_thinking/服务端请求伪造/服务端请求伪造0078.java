import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ThumbnailServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String imageUri = req.getParameter("imageUri");
        if (imageUri == null || imageUri.isEmpty()) return;

        try {
            URL url = new URL(imageUri);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            resp.setContentType("image/jpeg");
            OutputStream out = resp.getOutputStream();
            InputStream in = conn.getInputStream();
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            in.close();
            out.flush();
            
        } catch (Exception e) {
            try {
                resp.sendError(500, "Invalid image URL");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}

// web.xml配置
/*
<web-app>
    <servlet>
        <servlet-name>ThumbnailServlet</servlet-name>
        <servlet-class>ThumbnailServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <url-pattern>/thumbnail</url-pattern>
    </servlet-mapping>
</web-app>
*/