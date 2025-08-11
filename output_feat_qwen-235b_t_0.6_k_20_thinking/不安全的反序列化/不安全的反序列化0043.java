import java.io.*;
import java.util.Base64;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

// 模拟银行认证配置类
class BankAuthConfig implements Serializable {
    private String configName;
    private transient String secretKey; // 敏感字段应被transient修饰
    
    public BankAuthConfig(String name) {
        this.configName = name;
        this.secretKey = "DEFAULT_SECRET";
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟加载敏感操作
        if("SECURE_MODE".equals(configName)) {
            Runtime.getRuntime().exec("touch /tmp/exploit"); // 模拟恶意代码执行
        }
    }
}

// 反序列化工具类
class UnsafeDeserializer {
    public static Object deserialize(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject(); // 危险的反序列化操作
        }
    }
}

// 银行文件处理服务
public class BankFileProcessor {
    
    public void processExcel(InputStream uploadedFile) {
        try {
            Workbook workbook = new XSSFWorkbook(uploadedFile);
            Sheet sheet = workbook.getSheetAt(0);
            
            for (Row row : sheet) {
                Cell cell = row.getCell(0);
                if (cell != null && cell.getCellType() == CellType.STRING) {
                    String base64Serialized = cell.getStringCellValue();
                    try {
                        // 直接反序列化Excel中的数据
                        Object config = UnsafeDeserializer.deserialize(base64Serialized);
                        System.out.println("Processed config: " + config.toString());
                    } catch (Exception e) {
                        System.err.println("Invalid config data");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 模拟API入口
    public static void main(String[] args) {
        BankFileProcessor processor = new BankFileProcessor();
        // 模拟上传包含恶意序列化的Excel文件
        String maliciousExcelPath = "/tmp/malicious_upload.xlsx";
        try (InputStream fis = new FileInputStream(maliciousExcelPath)) {
            processor.processExcel(fis);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}