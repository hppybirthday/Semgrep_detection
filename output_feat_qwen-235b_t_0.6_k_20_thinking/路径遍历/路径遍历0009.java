import java.io.*;
import java.nio.file.*;
import java.util.*;

interface TemplateValidator {
    boolean validateTemplate(String content);
}

abstract class FileGenerator {
    protected TemplateValidator validator;
    protected String baseDir;
    
    public FileGenerator(TemplateValidator validator, String baseDir) {
        this.validator = validator;
        this.baseDir = baseDir;
    }
    
    public abstract boolean generateFile(String viewName, String content) throws IOException;
}

class BladeCodeGenerator extends FileGenerator {
    public BladeCodeGenerator(TemplateValidator validator, String baseDir) {
        super(validator, baseDir);
    }

    @Override
    public boolean generateFile(String viewName, String content) throws IOException {
        Path templatePath = Paths.get(baseDir);
        Path targetPath = templatePath.resolve(viewName);
        
        // 模拟大数据处理前的模板校验
        if (!validator.validateTemplate(content)) {
            return false;
        }
        
        try (BufferedWriter writer = Files.newBufferedWriter(targetPath)) {
            writer.write(content);
            return true;
        }
    }
}

class TemplateConfig {
    public static final String TEMPLATE_ROOT = "/data/template/";
}

public class VulnerableBigDataApp {
    public static void main(String[] args) {
        TemplateValidator strictValidator = new TemplateValidator() {
            @Override
            public boolean validateTemplate(String content) {
                // 简化的大数据模板校验逻辑
                return content.contains("BIG_DATA_SCHEMA");
            }
        };
        
        FileGenerator generator = new BladeCodeGenerator(
            strictValidator, 
            TemplateConfig.TEMPLATE_ROOT
        );
        
        // 模拟用户输入导致的路径遍历攻击
        String userInput = "../../etc/passwd"; // 恶意输入
        String templateContent = "BIG_DATA_SCHEMA: sensitive_data_access";
        
        try {
            boolean success = generator.generateFile(userInput, templateContent);
            System.out.println("File generated: " + success);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}