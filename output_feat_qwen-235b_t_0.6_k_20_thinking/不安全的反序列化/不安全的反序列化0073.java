import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.web.bind.annotation.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.*;
import java.util.Map;

@RestController
@RequestMapping("/data")
public class DataProcessor {
    
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            Workbook workbook = new XSSFWorkbook(file.getInputStream());
            Sheet sheet = workbook.getSheetAt(0);
            
            // 模拟从Excel读取配置数据
            Row configRow = sheet.getRow(1);
            Cell configCell = configRow.getCell(0);
            String jsonConfig = configCell.getStringCellValue();
            
            // 危险的反序列化操作
            SystemState state = JSON.parseObject(jsonConfig, SystemState.class, Feature.SupportNonPublicField);
            
            // 模拟处理大数据
            return "Processed " + state.getDataSize() + " records successfully";
            
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }
}

// 可序列化的状态类
class SystemState {
    private Map<String, Object> config;
    private int dataSize;
    
    public Map<String, Object> getConfig() { return config; }
    public void setConfig(Map<String, Object> config) { this.config = config; }
    
    public int getDataSize() { return dataSize; }
    public void setDataSize(int dataSize) { this.dataSize = dataSize; }
    
    // 模拟从工作簿反序列化（真实场景中可能从Excel读取）
    public static SystemState deserialize(String json) {
        // 未验证类型直接反序列化
        return JSON.parseObject(json, SystemState.class, Feature.SupportNonPublicField);
    }
}

// 攻击者可构造的恶意类
class MaliciousPayload {
    static {
        try {
            // 在静态代码块中执行任意命令
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}