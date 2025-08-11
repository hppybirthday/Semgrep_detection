import java.io.*;
import java.nio.file.*;
import java.util.*;

// 模拟任务管理系统中的主题模板服务类
public class TemplateService {
    // 模拟模板检查接口
    public boolean checkTemplate(String templateName) {
        try {
            // 漏洞点：直接拼接用户输入到文件路径
            String basePath = "templates/";
            String filePath = basePath + templateName + ".tpl";
            
            // 调用元编程风格的代码生成器
            BladeCodeGenerator.run(filePath);
            return true;
        } catch (Exception e) {
            System.out.println("[ERROR] 模板检查失败: " + e.getMessage());
            return false;
        }
    }

    // 模拟攻击者调用入口
    public static void main(String[] args) {
        TemplateService service = new TemplateService();
        if (args.length > 0) {
            System.out.println("检查模板: " + args[0]);
            boolean result = service.checkTemplate(args[0]);
            System.out.println("检查结果: " + (result ? "有效" : "无效"));
        } else {
            System.out.println("Usage: java TemplateService <template_name>");
        }
    }
}

// 模拟Blade框架代码生成器
class BladeCodeGenerator {
    // 元编程风格的文件操作接口
    public static void run(String templatePath) throws Exception {
        // 漏洞触发点：直接使用未验证的路径
        File templateFile = new File(templatePath);
        
        // 模拟模板解析操作
        System.out.println("[DEBUG] 正在加载模板文件: " + templateFile.getAbsolutePath());
        
        // 实际可能存在的危险操作
        if (templateFile.exists()) {
            // 使用字节码读取模拟代码生成
            byte[] templateData = Files.readAllBytes(templateFile.toPath());
            System.out.println("[INFO] 模板大小: " + templateData.length + " bytes");
        } else {
            throw new FileNotFoundException("模板文件不存在");
        }
    }
}

/*
攻击示例：
1. 正常调用：java TemplateService default_theme
   -> 检查 templates/default_theme.tpl
2. 路径遍历攻击：java TemplateService ../../etc/passwd
   -> 尝试访问 /etc/passwd（Linux）或 ..\\..\\..\\etc\\passwd（Windows）
3. 绝对路径攻击（Windows）：java TemplateService C:/Windows/System32/drivers/etc/hosts
*/