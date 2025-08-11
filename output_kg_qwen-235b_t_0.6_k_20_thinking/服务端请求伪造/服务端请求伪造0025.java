package com.example.bigdata.processor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

/**
 * 大数据处理作业配置处理器
 * 使用反射动态设置输入路径导致SSRF漏洞
 */
public class JobConfigServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        try {
            // 获取用户输入的外部数据源URL
            String dataSourceUrl = request.getParameter("source");
            if (dataSourceUrl == null || dataSourceUrl.isEmpty()) {
                response.getWriter().write("Missing data source parameter");
                return;
            }

            // 创建Hadoop配置对象
            Configuration conf = new Configuration();
            conf.set("fs.defaultFS", "file:///");

            // 使用反射动态创建MapReduce作业
            Class<?> jobClass = Class.forName("org.apache.hadoop.mapreduce.Job");
            Method getInstanceMethod = jobClass.getMethod("getInstance", Configuration.class);
            Object jobInstance = getInstanceMethod.invoke(null, conf);

            // 动态设置输入路径（存在漏洞的关键点）
            Method setInputPathsMethod = FileInputFormat.class.getMethod(
                "setInputPaths", Job.class, Path[].class);
            
            // 直接使用用户输入构造Path对象
            Path[] inputPaths = new Path[] { new Path(dataSourceUrl) };
            setInputPathsMethod.invoke(null, jobInstance, inputPaths);

            // 设置输出路径（为简化示例硬编码）
            FileOutputFormat.setOutputPath(
                (Job) jobInstance, 
                new Path("/user/hadoop/output")
            );

            // 模拟执行作业（实际不会真正执行）
            response.getWriter().write("Processing data from: " + dataSourceUrl);
            
            // 漏洞利用示例：读取本地文件
            if (dataSourceUrl.startsWith("file:///etc/")) {
                BufferedReader br = new BufferedReader(
                    new InputStreamReader(new URL(dataSourceUrl).openStream()));
                String line;
                while ((line = br.readLine()) != null) {
                    response.getWriter().write("\
" + line);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            try {
                response.getWriter().write("Error processing request: " + e.getMessage());
            } catch (Exception ex) {
                // 忽略
            }
        }
    }
}

// Hadoop作业配置类（简化版）
class JobConfig {
    private String inputPath;
    private String outputPath;
    private String mapperClass;
    private String reducerClass;
    // 实际会有更多配置项...

    public void setInputPath(String inputPath) {
        this.inputPath = inputPath;
    }

    public String getInputPath() {
        return inputPath;
    }
}