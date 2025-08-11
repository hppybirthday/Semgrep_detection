import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDate;
import java.util.UUID;
import java.util.function.Function;

public class VulnerableWebApp {
    public static void main(String[] args) {
        // 模拟Web请求处理
        Function<String, String> deleteHandler = bizType -> {
            try {
                String basePath = "/var/www/uploads/" + LocalDate.now().toString() + "/" + UUID.randomUUID().toString();
                String safePath = basePath + "/" + bizType + ".txt";
                FileUtil.writeString(safePath, "DELETE_CONFIRMED");
                return "Deleted: " + bizType;
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        };

        // 模拟攻击请求
        System.out.println(deleteHandler.apply("../../etc/passwd"));
    }
}

class FileUtil {
    public static void writeString(String path, String content) throws IOException {
        File file = new File(path);
        // 强制创建父目录
        file.getParentFile().mkdirs();
        
        // 存在漏洞：未校验路径中的../序列
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}

/*
编译运行后将产生以下攻击面：
1. 构造恶意路径：curl http://api.example.com/delete?bizType=../../etc/passwd
2. 路径解析过程：
   原始路径：/var/www/uploads/2023-10-15/uuid/../../etc/passwd.txt
   实际解析：/var/www/etc/passwd.txt （Linux系统）
   实际解析：C:\\var\\www\\etc\\passwd.txt （Windows系统）
3. 攻击者可覆盖任意文件，例如：
   - 覆盖web配置文件
   - 修改数据库连接文件
   - 注入恶意脚本
*/