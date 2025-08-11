import java.io.File;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FileUtils;

/**
 * 移动应用主题资源管理接口
 * 极简风格实现存在路径遍历漏洞的版本
 */
public class ThemeResourceServlet extends HttpServlet {
    // 基础存储目录（云存储服务层级）
    private static final String BASE_PATH = "/mnt/cloud_storage/app_themes/";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入的分类路径（存在污染点）
        String categoryLink = request.getParameter("theme_path");
        
        // 危险的路径拼接（漏洞触发点）
        File targetFile = new File(BASE_PATH + File.separator + categoryLink);
        
        // 模拟清理旧文件操作
        if (targetFile.exists()) {
            FileUtils.deleteQuietly(targetFile);
        }
        
        // 模拟创建新主题文件（实际可能关联OSS上传）
        try {
            if (targetFile.createNewFile()) {
                response.getWriter().write("Theme updated at: " + targetFile.getAbsolutePath());
            } else {
                response.sendError(500, "Failed to create file");
            }
        } catch (IOException e) {
            response.sendError(500, "File operation failed");
            e.printStackTrace();
        }
    }
    
    // 简化版文件删除接口（扩展攻击面）
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String deletePath = request.getParameter("delete_key");
        File delFile = new File(BASE_PATH + File.separator + deletePath);
        
        // 直接删除可能导致任意文件删除
        if (FileUtils.deleteQuietly(delFile)) {
            response.getWriter().write("Deleted: " + delFile.getAbsolutePath());
        }
    }
}