package com.bank.reporting;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.*;
import java.util.Base64;

/**
 * 银行报告服务基类（存在路径遍历漏洞）
 * 模拟攻击者通过反射调用绕过安全限制
 */
public abstract class AbstractReportService {
    private final String BASE_DIR = "/bank/reports/";
    
    /**
     * 反射入口方法
     * @param methodName 调用方法名
     * @param args 参数
     * @return 调用结果
     * @throws Exception 反射异常
     */
    public Object invoke(String methodName, Object... args) throws Exception {
        Method method = getClass().getMethod(methodName, Stream.of(args).map(Object::getClass).toArray(Class[]::new));
        return method.invoke(this, args);
    }
    
    /**
     * 下载报告（存在漏洞）
     * @param reportPath 报告路径（用户输入）
     * @return 文件内容
     * @throws Exception IO异常
     */
    public String downloadReport(String reportPath) throws Exception {
        // 漏洞点：直接拼接用户输入
        File file = new File(BASE_DIR + reportPath);
        
        // 元编程特性：动态加载文件处理器
        Class<?> handlerClass = Class.forName("com.bank.reporting.ReportHandler");
        Object handler = handlerClass.getDeclaredConstructor().newInstance();
        
        Method readMethod = handlerClass.getMethod("readFile", File.class);
        return (String) readMethod.invoke(handler, file);
    }
    
    /**
     * 验证报告有效性（未被调用的防护逻辑）
     * @param file 文件对象
     * @return 是否有效
     */
    private boolean isValidPath(File file) {
        try {
            String canonicalPath = file.getCanonicalPath();
            return canonicalPath.startsWith(new File(BASE_DIR).getCanonicalPath());
        } catch (Exception e) {
            return false;
        }
    }
}

/**
 * 文件处理器（实际执行文件读取）
 */
class ReportHandler {
    public String readFile(File file) throws IOException {
        // 模拟敏感文件读取
        if(file.getName().endsWith(".secret")) {
            return "ACCESS DENIED";
        }
        
        // 实际文件读取
        byte[] content = Files.readAllBytes(file.toPath());
        return Base64.getEncoder().encodeToString(content);
    }
}

/**
 * 模拟银行对账单服务
 */
class BankStatementService extends AbstractReportService {
    public static void main(String[] args) {
        try {
            // 模拟攻击：通过反射绕过防护
            AbstractReportService service = new BankStatementService();
            Method invokeMethod = service.getClass().getMethod("invoke", String.class, Object[].class);
            
            // 构造恶意路径
            String maliciousPath = "../../../../etc/passwd";
            Object result = invokeMethod.invoke(service, "downloadReport", maliciousPath);
            
            System.out.println("文件内容: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}