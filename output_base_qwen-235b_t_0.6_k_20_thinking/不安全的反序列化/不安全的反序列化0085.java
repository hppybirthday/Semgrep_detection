import java.io.*;
import java.lang.reflect.Method;
import java.util.Base64;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    
    // 模拟企业级服务中需要传输序列化对象的场景
    @PostMapping("/process")
    public String processSerializedData(@RequestBody String payload) {
        try {
            // 将Base64字符串解码为字节流
            byte[] data = Base64.getDecoder().decode(payload);
            
            // 创建自定义类加载器（元编程关键点）
            ClassLoader dynamicLoader = new ClassLoader() {
                @Override
                public Class<?> loadClass(String name) throws ClassNotFoundException {
                    if (name.equals("MaliciousClass")) {
                        // 动态生成恶意类字节码（元编程体现）
                        String code = "import java.io.*; public class MaliciousClass implements Serializable { " +
                            "private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException { " +
                            "Runtime.getRuntime().exec(\\"calc\\"); " + // 恶意命令执行
                            "in.defaultReadObject(); } }";
                        byte[] bytecode = compileJavaCode(code);
                        return defineClass(name, bytecode, 0, bytecode.length);
                    }
                    return super.loadClass(name);
                }
                
                // 简单的内存编译器模拟（实际攻击中可能通过其他方式注入）
                private byte[] compileJavaCode(String code) {
                    // 实际攻击中可能通过JNI或远程加载等方式实现
                    return new byte[0];
                }
            };
            
            // 创建自定义ObjectInputStream（突破默认类加载器限制）
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    return dynamicLoader.loadClass(desc.getName());
                }
            };
            
            // 危险的反序列化操作（漏洞核心触发点）
            Object obj = ois.readObject();
            return "Processed: " + obj.getClass().getName();
            
        } catch (Exception e) {
            return "Error processing data: " + e.getMessage();
        }
    }
    
    // 模拟企业级服务中的数据模型
    public static class UserData implements Serializable {
        private String username;
        private transient String sensitiveData; // 敏感字段
        
        public UserData(String username) {
            this.username = username;
        }
        
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 实际业务中可能包含敏感操作
            if (sensitiveData != null) {
                System.out.println("Loading sensitive data: " + sensitiveData);
            }
        }
    }
}