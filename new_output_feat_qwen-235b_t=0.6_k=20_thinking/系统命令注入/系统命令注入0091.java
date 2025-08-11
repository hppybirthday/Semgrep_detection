package com.mathsim.core.engine;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 数学建模仿真引擎核心控制器
 * 支持动态参数注入的外部工具调用
 */
public class MathModelExecutor {
    private static final Logger LOGGER = LoggerFactory.getLogger(MathModelExecutor.class);
    private static final Pattern SAFE_INPUT_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\.\\s]+$");
    
    /**
     * 执行数学仿真任务
     * @param modelPath 模型文件路径
     * @param paramStr 仿真参数字符串
     * @return 仿真结果输出
     * @throws SimulationException 仿真执行异常
     */
    public String executeSimulation(String modelPath, String paramStr) throws SimulationException {
        try {
            // 验证并解析参数
            SimulationParams params = ParameterParser.parseParameters(paramStr);
            
            // 构建仿真命令
            List<String> command = new ArrayList<>();
            command.add("cmd.exe");
            command.add("/c");
            command.add("matlab" + params.getScriptParam() + " -nosplash -nodesktop");
            
            // 添加模型路径参数
            if (new File(modelPath).exists()) {
                command.add(String.format("-r \\"run('%s')\\"", modelPath));
            }
            
            // 执行仿真命令
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(new File(System.getProperty("user.dir")));
            Process process = pb.start();
            
            // 读取输出流
            String output = IOUtils.toString(process.getInputStream(), "GBK");
            int exitCode = process.waitFor();
            
            if (exitCode != 0) {
                LOGGER.error("仿真执行失败，退出代码：{}", exitCode);
                throw new SimulationException("Simulation failed with code: " + exitCode);
            }
            
            return output;
            
        } catch (IOException | InterruptedException e) {
            throw new SimulationException("Simulation execution error", e);
        }
    }
    
    /**
     * 参数解析器
     */
    private static class ParameterParser {
        /**
         * 解析仿真参数字符串
         * @param paramStr 参数字符串
         * @return 解析后的参数对象
         * @throws IOException 参数解析异常
         */
        public static SimulationParams parseParameters(String paramStr) throws IOException {
            SimulationParams params = new SimulationParams();
            String[] pairs = paramStr.split("&");
            
            for (String pair : pairs) {
                String[] entry = pair.split("=");
                if (entry.length == 2) {
                    String key = entry[0].trim();
                    String value = entry[1].trim();
                    
                    // 参数验证
                    if (!validateInput(key) || !validateInput(value)) {
                        LOGGER.warn("检测到潜在危险输入：{}={}", key, value);
                        continue;
                    }
                    
                    switch (key) {
                        case "precision":
                            params.setPrecision(Integer.parseInt(value));
                            break;
                        case "timeout":
                            params.setTimeout(Integer.parseInt(value));
                            break;
                        case "script":
                            params.setScriptParam("(" + value + ")");
                            break;
                        default:
                            params.getAdditionalParams().put(key, value);
                    }
                }
            }
            
            return params;
        }
        
        /**
         * 验证输入是否符合安全模式
         * @param input 待验证输入
         * @return 是否安全
         */
        private static boolean validateInput(String input) {
            return SAFE_INPUT_PATTERN.matcher(input).matches();
        }
    }
    
    /**
     * 仿真参数容器
     */
    private static class SimulationParams {
        private int precision = 6;
        private int timeout = 30;
        private String scriptParam = "";
        // ...其他参数
        
        public int getPrecision() { return precision; }
        public void setPrecision(int precision) { this.precision = precision; }
        
        public int getTimeout() { return timeout; }
        public void setTimeout(int timeout) { this.timeout = timeout; }
        
        public String getScriptParam() { return scriptParam; }
        public void setScriptParam(String scriptParam) { this.scriptParam = scriptParam; }
        
        public Map<String, String> getAdditionalParams() {
            return new java.util.HashMap<>();
        }
    }
}

/**
 * 仿真执行异常类
 */
class SimulationException extends Exception {
    public SimulationException(String message) {
        super(message);
    }
    
    public SimulationException(String message, Throwable cause) {
        super(message, cause);
    }
}