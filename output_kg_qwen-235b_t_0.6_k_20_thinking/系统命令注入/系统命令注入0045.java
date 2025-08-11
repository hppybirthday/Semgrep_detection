package com.mathsim;

import java.lang.reflect.Method;
import java.util.Scanner;

/**
 * 数学建模仿真系统
 * 使用元编程动态调用计算引擎
 */
public class MathModelSimulator {
    // 动态生成计算类
    public static String generateCalcClass(String formula) {
        return "package com.mathsim.engine;\
" +
               "public class DynamicCalc {\
" +
               "    public double calculate(String input) {\
" +
               "        return " + formula + ";\
" +
               "    }\
" +
               "}";
    }

    // 反射执行计算
    public static double executeCalculation(String formula, String userInput) throws Exception {
        // 动态编译并加载类
        Class<?> calcClass = new JavaClassCompiler().compile("com.mathsim.engine.DynamicCalc", generateCalcClass(formula));
        Object calcInstance = calcClass.getDeclaredConstructor().newInstance();
        
        // 反射调用计算方法
        Method calculateMethod = calcClass.getMethod("calculate", String.class);
        
        // 危险的系统命令调用
        String cmd = (String) calculateMethod.invoke(calcInstance, userInput);
        return CommandExecutor.execCommand(cmd);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("数学建模仿真系统 v1.0");
        System.out.println("请输入计算公式（示例：Math.sqrt(Double.parseDouble(input))）:");
        String formula = scanner.nextLine();
        
        System.out.println("请输入计算参数:");
        String userInput = scanner.nextLine();
        
        try {
            double result = executeCalculation(formula, userInput);
            System.out.println("计算结果: " + result);
        } catch (Exception e) {
            System.err.println("计算错误: " + e.getMessage());
        }
    }
}

// 模拟动态编译器
class JavaClassCompiler {
    public Class<?> compile(String className, String classCode) {
        // 实际实现应包含动态编译逻辑
        // 此处简化返回虚假的Class对象
        return null;
    }
}

// 危险的命令执行器
class CommandExecutor {
    public static double execCommand(String cmd) throws Exception {
        // 存在漏洞的命令执行方式
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        
        // 简化处理：假设命令返回数值结果
        java.io.BufferedReader reader = new java.io.BufferedReader(
            new java.io.InputStreamReader(process.getInputStream()));
        
        String line = reader.readLine();
        process.destroy();
        
        return Double.parseDouble(line);
    }
}