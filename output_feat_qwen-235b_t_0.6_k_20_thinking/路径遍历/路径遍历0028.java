import java.io.*;
import java.nio.file.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ThemeLoader extends HttpServlet {
    private static final String BASE_DIR = "/var/www/crm/resources/";
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            String category = req.getParameter("categoryPath");
            String articleId = req.getParameter("articleId");
            
            // Vulnerable path construction
            String filePath = BASE_DIR + category + File.separator + articleId;
            File targetFile = new File(filePath);
            
            if (targetFile.getCanonicalPath().startsWith(BASE_DIR)) {
                if (Files.isDirectory(targetFile.toPath())) {
                    Files.write(targetFile.toPath(), "new content".getBytes());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(8080);
            while (true) {
                new Thread(() -> {
                    try {
                        Socket s = ss.accept();
                        BufferedReader in = new BufferedReader(
                            new InputStreamReader(s.getInputStream()));
                        String line;
                        while (!(line = in.readLine()).isEmpty()) {
                            // Simulated request parsing
                            if (line.startsWith("GET /load")) {
                                String query = line.split("\\\\?")[1].split(" ")[0];
                                String[] params = query.split("&");
                                String category = params[0].split("=")[1];
                                String articleId = params[1].split("=")[1];
                                // Vulnerable path construction
                                String filePath = BASE_DIR + category + File.separator + articleId;
                                File targetFile = new File(filePath);
                                System.out.println("Accessing: " + targetFile.getAbsolutePath());
                            }
                        }
                    } catch (Exception e) {}
                }).start();
            }
        } catch (Exception e) {}
    }
}