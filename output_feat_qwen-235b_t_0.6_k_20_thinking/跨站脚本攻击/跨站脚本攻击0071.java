import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.*;

public class GameServer {
    public static void main(String[] args) throws Exception {
        Server server = new Server(8080);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);

        context.addServlet(new ServletHolder(new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                String callback = req.getParameter("callback");
                String gameData = "{\\"rank\\":1,\\"player\\":\\"Guest\\"}";
                
                resp.setContentType("application/javascript");
                PrintWriter out = resp.getWriter();
                // 漏洞点：直接拼接用户输入的callback参数
                out.print(callback + "(" + gameData + ")");
            }
        }), "/leaderboard/*");

        server.start();
        System.out.println("Game server started on port 8080");
    }
}

// pom.xml依赖配置示例：
// <dependency>
//     <groupId>org.eclipse.jetty</groupId>
//     <artifactId>jetty-server</artifactId>
//     <version>9.4.44.v20210927</version>
// </dependency>
// <dependency>
//     <groupId>org.eclipse.jetty</groupId>
//     <artifactId>jetty-servlet</artifactId>
//     <version>9.4.44.v20210927</version>
// </dependency>