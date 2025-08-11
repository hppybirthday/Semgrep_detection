import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import javax.servlet.*;
import javax.servlet.http.*;

public class PluginUploadServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/www/data/plugins/";
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String prefix = request.getParameter("prefix");
        String suffix = request.getParameter("suffix");
        String content = request.getParameter("content");
        
        if(prefix == null || suffix == null || content == null) {
            response.sendError(400, "Missing parameters");
            return;
        }
        
        String safePath = getPath(prefix, suffix);
        File targetFile = new File(safePath);
        
        // 模拟爬虫插件存储的业务场景
        if(!safePath.startsWith(BASE_DIR)) {
            response.sendError(403, "Invalid path");
            return;
        }
        
        try {
            FileUtil.writeString(content, targetFile);
            response.getWriter().write("Plugin saved successfully");
        } catch (Exception e) {
            response.sendError(500, "Internal server error");
        }
    }
    
    private String getPath(String prefix, String suffix) {
        String dateDir = new SimpleDateFormat("yyyy/MM/dd").format(new Date());
        String uuid = UUID.randomUUID().toString();
        // 漏洞点：直接拼接用户输入到路径中
        return BASE_DIR + prefix + "/" + dateDir + "/" + uuid + suffix;
    }
}

class FileUtil {
    static void writeString(String content, File file) throws IOException {
        if(!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
        }
    }
}