package com.example.mlapp.filter;

import com.example.mlapp.service.DataProcessor;
import com.example.mlapp.util.LoggerUtil;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class DataProcessingFilter implements Filter {
    private DataProcessor dataProcessor = new DataProcessor();

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String cmdParam = httpRequest.getParameter("cmd_");
        
        if (cmdParam != null && !cmdParam.isEmpty()) {
            try {
                // 记录原始输入用于审计
                LoggerUtil.logInput(cmdParam);
                
                // 调用数据处理服务执行命令
                String result = dataProcessor.processData(cmdParam);
                request.setAttribute("result", result);
            } catch (Exception e) {
                LoggerUtil.logError("Processing failed: " + e.getMessage());
                request.setAttribute("error", "Internal server error");
            }
        }
        
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}
}

package com.example.mlapp.service;

import com.example.mlapp.util.PythonScriptExecutor;
import com.example.mlapp.util.SecurityValidator;
import java.util.Map;

public class DataProcessor {
    private PythonScriptExecutor scriptExecutor = new PythonScriptExecutor();
    
    public String processData(String userInput) throws Exception {
        // 模拟机器学习预处理流程
        if (!SecurityValidator.isValidDataset(userInput)) {
            throw new IllegalArgumentException("Invalid dataset format");
        }
        
        // 构造Python脚本参数（存在漏洞的关键点）
        Map<String, String> params = buildProcessingParams(userInput);
        
        // 执行数据处理脚本
        return scriptExecutor.executeScript("preprocess.py", params);
    }
    
    private Map<String, String> buildProcessingParams(String userInput) {
        // 实际漏洞隐藏点：userInput未经充分过滤直接拼接
        return Map.of(
            "input_path", "/data/sets/" + userInput,
            "output_path", "/data/processed/" + userInput + "_processed"
        );
    }
}

package com.example.mlapp.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class PythonScriptExecutor {
    public String executeScript(String scriptName, Map<String, String> params) throws IOException {
        StringBuilder command = new StringBuilder("python3 " + scriptName);
        
        // 构造命令行参数（危险的拼接方式）
        for (Map.Entry<String, String> entry : params.entrySet()) {
            command.append(" --").append(entry.getKey()).append(" ").append(entry.getValue());
        }
        
        try {
            Process process = Runtime.getRuntime().exec(command.toString());
            
            // 读取执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            throw new IOException("Script execution failed: " + e.getMessage());
        }
    }
}

package com.example.mlapp.util;

import java.util.regex.Pattern;

public class SecurityValidator {
    // 误导性安全检查：只验证文件扩展名
    public static boolean isValidDataset(String filename) {
        return Pattern.matches(".*\\.csv$", filename);
    }
}

package com.example.mlapp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggerUtil {
    private static final Logger logger = LoggerFactory.getLogger("DataProcessingLogger");
    
    public static void logInput(String input) {
        logger.info("Received input: {}", input);
    }
    
    public static void logError(String message) {
        logger.error(message);
    }
}