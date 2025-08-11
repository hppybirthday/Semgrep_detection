import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;

/**
 * 数学模型仿真系统
 * 存在路径遍历漏洞的示例
 */
public class MathModelSimulator {
    public static void main(String[] args) {
        System.out.println("数学模型仿真系统");
        System.out.print("请输入模型配置文件名: ");
        Scanner scanner = new Scanner(System.in);
        String userInput = scanner.nextLine();
        
        try {
            ModelLoader loader = new ModelLoader("/var/math_models");
            MathematicalModel model = loader.loadModel(userInput);
            System.out.println("模型加载成功: " + model.getName());
            System.out.println("模型参数: " + model.getParameters());
        } catch (Exception e) {
            System.err.println("加载失败: " + e.getMessage());
        }
    }
}

class MathematicalModel {
    private String name;
    private String parameters;
    
    public MathematicalModel(String name, String parameters) {
        this.name = name;
        this.parameters = parameters;
    }
    
    public String getName() {
        return name;
    }
    
    public String getParameters() {
        return parameters;
    }
}

class ModelLoader {
    private String baseDirectory;
    
    public ModelLoader(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }
    
    /**
     * 存在路径遍历漏洞的模型加载方法
     * 漏洞点：直接拼接用户输入的文件名，未进行路径规范化检查
     * 攻击者可通过输入"../../../../../etc/passwd"读取敏感文件
     */
    public MathematicalModel loadModel(String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入到文件路径中
        File modelFile = new File(baseDirectory + "/" + fileName);
        
        if (!modelFile.exists()) {
            throw new IOException("模型文件不存在");
        }
        
        // 读取模型文件内容
        FileInputStream fis = new FileInputStream(modelFile);
        byte[] data = new byte[(int) modelFile.length()];
        fis.read(data);
        fis.close();
        
        // 模拟解析模型内容
        String content = new String(data);
        String[] parts = content.split("@PARAMS@");
        
        return new MathematicalModel(
            modelFile.getName(), 
            parts.length > 1 ? parts[1] : "无参数"
        );
    }
    
    /**
     * 修复后的版本应该包含路径规范化检查
     * protected MathematicalModel loadModelSecure(String fileName) throws IOException {
     *     File modelFile = new File(baseDirectory + "/" + fileName);
     *     // 获取规范化路径
     *     String canonicalPath = modelFile.getCanonicalPath();
     *     // 验证路径是否在允许的目录范围内
     *     if (!canonicalPath.startsWith(new File(baseDirectory).getCanonicalPath())) {
     *         throw new IOException("非法路径访问");
     *     }
     *     // 后续处理...
     * }
     */
}