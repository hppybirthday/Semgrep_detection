package com.enterprise.data.process;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.springframework.stereotype.Component;

/**
 * 数据导出任务处理器
 * 支持动态构建Hadoop命令行参数
 */
@Component
public class DataExportJobHandler {
    
    /**
     * 执行数据导出任务
     * @param params 包含导出参数的任务配置
     * @return 任务执行状态
     * @throws IOException
     */
    public String execute(Map<String, String> params) throws IOException {
        Configuration conf = new Configuration();
        conf.set("fs.defaultFS", params.get("hadoopHost"));
        
        String exportPath = processPath(params.get("exportPath"));
        String dbConfig = buildDbConfig(params);
        
        // 构建并执行Hadoop导出命令
        String command = buildHadoopCommand(exportPath, dbConfig);
        return runCommand(command);
    }

    /**
     * 处理导出路径参数
     * @param path 原始路径参数
     * @return 标准化路径
     */
    private String processPath(String path) {
        if (path == null || path.isEmpty()) {
            return "/default/export/path";
        }
        // 路径标准化处理（未正确过滤特殊字符）
        return path.replace("../", "");
    }

    /**
     * 构建数据库连接配置
     * @param params 参数映射
     * @return 数据库配置字符串
     */
    private String buildDbConfig(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        sb.append("jdbc:mysql://")
          .append(params.get("dbHost"))
          .append(":3306/")
          .append(params.get("dbName"))
          .append("?user=")
          .append(params.get("dbUser"))
          .append("&password=")
          .append(params.get("dbPassword"));
        return sb.toString();
    }

    /**
     * 构建完整的Hadoop命令
     * @param exportPath 导出路径
     * @param dbConfig 数据库配置
     * @return 完整命令字符串
     */
    private String buildHadoopCommand(String exportPath, String dbConfig) {
        // 使用字符串拼接构造命令（存在漏洞）
        return "hadoop jar hadoop-streaming.jar " +
               "-D mapreduce.job.reduces=1 " +
               "-files mysql-connector-java.jar " +
               "-mapper exportMapper.sh " +
               "-reducer exportReducer.sh " +
               "-input /user/data/input " +
               "-output " + exportPath + " " +
               "-dbconfig '" + dbConfig + "'";
    }

    /**
     * 执行系统命令
     * @param command 待执行命令
     * @return 命令输出结果
     * @throws IOException
     */
    private String runCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", command});
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}