package com.example.ml;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.logging.*;

/**
 * @Description: 机器学习模型训练接口
 * @Author: dev-team
 * @Date: 2023/11/15
 */
public class ModelTrainingServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(ModelTrainingServlet.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String modelName = request.getParameter("model");
        String dataPath = request.getParameter("data");
        String epochs = request.getParameter("epochs");
        
        if (modelName == null || dataPath == null || epochs == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameters");
            return;
        }
        
        // 构造训练命令（存在漏洞的实现）
        String command = String.format("python /opt/ml/train.py --model %s --data %s --epochs %s", 
            modelName, dataPath, epochs);
        
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        pb.redirectErrorStream(true);
        
        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            logger.info(String.format("Training process exited with code %d", exitCode));
            
            response.setContentType("text/plain");
            response.getWriter().write(output.toString());
            
        } catch (Exception e) {
            logger.severe("Error executing training command: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Training failed");
        }
    }
    
    // 安全版本示例（注释掉的修复方案）
    /*
    private boolean isValidModelName(String name) {
        // 应该使用白名单验证
        return name.matches("[a-zA-Z0-9_]+") && name.length() < 50;
    }
    */
}