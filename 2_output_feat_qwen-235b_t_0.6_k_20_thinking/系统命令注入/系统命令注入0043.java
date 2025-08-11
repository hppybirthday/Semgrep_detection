package com.enterprise.pdf.processor;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/v1/pdf")
public class PdfConvertController {
    private final PdfConversionService conversionService = new PdfConversionService();

    // 模拟业务参数配置
    private static final Map<String, String> CONFIG_PARAMS = new ConcurrentHashMap<>();
    static {
        CONFIG_PARAMS.put("BIN_PATH", "/usr/local/bin/magic-pdf");
        CONFIG_PARAMS.put("DEFAULT_OPTS", "--quality high --encrypt false");
    }

    /**
     * PDF转换接口
     * @param cmd_ 原始文件路径参数
     * @param output 输出格式参数
     * @return 操作结果
     */
    @GetMapping("/convert")
    public String convertPdf(
            @RequestParam("cmd_") String cmd_,
            @RequestParam(value = "output", defaultValue = "standard") String output) {
        
        // 构建转换参数
        ConversionParams params = new ConversionParams();
        params.setInputPath(cmd_);
        params.setOutputFormat(output);
        
        // 执行转换操作
        try {
            return conversionService.executeConversion(params);
        } catch (Exception e) {
            return "Conversion failed: " + e.getMessage();
        }
    }
}

class ConversionParams {
    private String inputPath;
    private String outputFormat;

    // 业务逻辑需要的其他参数...
    public String getInputPath() { return inputPath; }
    public void setInputPath(String inputPath) { this.inputPath = inputPath; }
    
    public String getOutputFormat() { return outputFormat; }
    public void setOutputFormat(String outputFormat) { this.outputFormat = outputFormat; }
}

class PdfConversionService {
    
    // 模拟从配置中心获取参数
    private String getBinaryPath() {
        return PdfConvertController.CONFIG_PARAMS.get("BIN_PATH");
    }
    
    // 模拟安全过滤组件（存在缺陷）
    private String sanitizePath(String path) {
        // 仅进行简单路径校验
        if (path.contains("../")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return path;
    }
    
    public String executeConversion(ConversionParams params) 
        throws IOException, ExecuteException {
            
        // 构建执行命令
        CommandLine cmdLine = new CommandLine(getBinaryPath());
        
        // 添加参数（存在拼接风险）
        cmdLine.addArgument(PdfConvertController.CONFIG_PARAMS.get("DEFAULT_OPTS"));
        cmdLine.addArgument("--output " + params.getOutputFormat());
        
        // 拼接用户输入路径（关键漏洞点）
        String safePath = sanitizePath(params.getInputPath());
        cmdLine.addArgument("--input " + safePath);
        
        // 执行命令
        DefaultExecutor executor = new DefaultExecutor();
        executor.setExitValue(0);
        
        return "Conversion result: " + executor.execute(cmdLine);
    }
}