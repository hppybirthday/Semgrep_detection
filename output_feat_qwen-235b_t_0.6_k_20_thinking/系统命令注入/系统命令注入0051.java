import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/executeTask")
public class CommandJobHandler extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String taskName = request.getParameter("task");
        String param = request.getParameter("param");
        
        if (taskName == null || param == null) {
            response.getWriter().write("Missing parameters");
            return;
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            
            // 漏洞点：直接拼接用户输入到命令中
            String command = "echo '任务：" + taskName + "' && /usr/bin/echo 参数:" + param + " | /usr/bin/base64";
            
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                processBuilder.command("cmd.exe", "/c", command);
            } else {
                processBuilder.command("/bin/sh", "-c", command);
            }

            Process process = processBuilder.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            response.getWriter().write("执行结果 (退出码 " + exitCode + "):\
" + output.toString());
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.getWriter().write("任务执行被中断");
        } catch (IOException e) {
            response.getWriter().write("执行错误：" + e.getMessage());
        }
    }
}