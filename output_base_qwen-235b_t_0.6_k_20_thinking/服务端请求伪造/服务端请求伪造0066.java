import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.*;

public class ChatApp {
    public static void main(String[] args) throws Exception {
        Server server = new Server(8080);
        ServletContextHandler handler = new ServletContextHandler();
        handler.addServlet(ImageServlet.class, "/image/*");
        handler.addServlet(ChatServlet.class, "/chat/*");
        server.setHandler(handler);
        server.start();
        System.out.println("Server started on port 8080");
    }

    public static class ImageServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            String imageUrl = req.getParameter("url");
            if (imageUrl == null || imageUrl.isEmpty()) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing image URL");
                return;
            }

            try {
                URL url = new URL(imageUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                
                // Vulnerable: No validation of user-provided URL
                resp.setContentType("image/jpeg");
                try (InputStream in = conn.getInputStream();
                     OutputStream out = resp.getOutputStream()) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }
            } catch (Exception e) {
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Image fetch failed");
            }
        }
    }

    public static class ChatServlet extends HttpServlet {
        private static final List<String> messages = new ArrayList<>();

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            String user = req.getParameter("user");
            String message = req.getParameter("message");
            
            if (user == null || message == null) {
                resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
            
            messages.add("[" + user + "] " + message);
            resp.getWriter().write("Message sent\
");
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            resp.setContentType("text/plain");
            for (String msg : messages) {
                resp.getWriter().write(msg + "\
");
            }
        }
    }
}