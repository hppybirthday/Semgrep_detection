package com.crm.servlet;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.logging.*;

/**
 * @Description: CRM系统客户报告生成接口（存在命令注入漏洞）
 */
public class GenerateReportServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GenerateReportServlet.class.getName());

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String customerId = request.getParameter("id");
        if (customerId == null || customerId.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing customer ID");
            return;
        }

        // 模拟调用外部脚本生成报告（存在漏洞）
        Process process = null;
        try {
            // 危险的命令拼接方式
            String command = "/opt/scripts/generate_report.sh " + customerId;
            logger.info("Executing command: " + command);
            
            // 使用字符串拼接直接执行命令
            process = Runtime.getRuntime().exec(command);
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(response.getOutputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line + "\
");
            }
            
            int exitCode = process.waitFor();
            logger.info("Command exited with code " + exitCode);
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Command execution failed", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Report generation failed");
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
}