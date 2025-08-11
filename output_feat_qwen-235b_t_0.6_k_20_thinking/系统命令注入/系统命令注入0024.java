import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.logging.*;

/**
 * 机器学习模型预处理服务 - PDF文件转换接口
 * 使用第三方工具magic-pdf进行文档转换
 */
public class PDFProcessingServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(PDFProcessingServlet.class.getName());
    // 配置参数：转换工具路径
    private static final String MAGIC_PDF_PATH = "/opt/ml/tools/magic-pdf";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户提交的文件路径参数
        String filePath = request.getParameter("filePath");
        if (filePath == null || filePath.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file path");
            return;
        }

        // 防御式编程：尝试进行输入验证（存在缺陷的验证）
        if (!isValidPath(filePath)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path format");
            return;
        }

        try {
            // 漏洞点：直接拼接用户输入到系统命令
            String command = String.format("%s -process %s", MAGIC_PDF_PATH, filePath);
            logger.info(String.format("Executing command: %s", command));
            
            // 使用Runtime.exec执行系统命令
            Process process = Runtime.getRuntime().exec(command);
            
            // 处理命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                logger.info("Command output: " + line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                logger.severe("Command error: " + line);
            }
            
            int exitCode = process.waitFor();
            logger.info(String.format("Command exited with code %d", exitCode));
            
            response.getWriter().write(String.format("Processing completed with exit code %d", exitCode));
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Command execution failed", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Processing failed");
        }
    }

    /**
     * 简单的路径验证（存在安全缺陷）
     * 仅检查路径是否包含基本文件名字符
     */
    private boolean isValidPath(String path) {
        // 错误地认为只允许字母数字和基本路径符号即可
        return path.matches("[a-zA-Z0-9_\\-\\/\\.]+$");
    }
}