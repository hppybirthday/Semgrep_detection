package com.example.mathmod.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

/**
 * 系统配置服务类
 * 处理数学模型参数配置的导入导出
 */
@Service
public class ConfigService {
    /**
     * 更新系统配置参数
     * @param configData 配置数据
     */
    public void updateConfigs(String configData) {
        // 解析配置数据
        JSONObject configObj = JSON.parseObject(configData);
        // 更新数学模型参数
        MathModelConfig mathConfig = configObj.getObject("modelParams", MathModelConfig.class);
        // 应用新配置
        applyMathModelConfig(mathConfig);
    }

    private void applyMathModelConfig(MathModelConfig config) {
        // 实际应用配置的逻辑
        System.out.println("应用新模型参数: " + config.getIterations());
    }
}

/**
 * 数学模型配置类
 * 存储仿真计算的核心参数
 */
class MathModelConfig {
    private int iterations;
    private double precision;
    
    // Getter/Setter省略
    public int getIterations() { return iterations; }
    public void setIterations(int iterations) { this.iterations = iterations; }
    public double getPrecision() { return precision; }
    public void setPrecision(double precision) { this.precision = precision; }
}

/**
 * Excel解析服务类
 * 用于处理数学模型参数文件的导入
 */
@Service
class ExcelParser {
    private final ConfigService configService;

    public ExcelParser(ConfigService configService) {
        this.configService = configService;
    }

    /**
     * 解析上传的Excel文件
     * @param file 上传的Excel文件
     */
    public void parseExcelFile(MultipartFile file) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                String[] cells = line.split(",");
                // 第三列包含序列化后的配置数据
                if (cells.length > 3 && "CONFIG".equals(cells[1])) {
                    configService.updateConfigs(cells[2]);
                }
            }
        } catch (Exception e) {
            // 错误处理
        }
    }
}

/**
 * 配置控制器
 * 处理管理员上传配置文件的请求
 */
@RestController
@RequestMapping("/admin/config")
class ConfigController {
    private final ExcelParser excelParser;

    public ConfigController(ExcelParser excelParser) {
        this.excelParser = excelParser;
    }

    /**
     * 上传配置文件接口
     * @param file 配置文件
     */
    @PostMapping("/upload")
    public String handleConfigUpload(@RequestParam("file") MultipartFile file) {
        if (!file.isEmpty()) {
            excelParser.parseExcelFile(file);
            return "配置更新成功";
        }
        return "配置更新失败";
    }
}