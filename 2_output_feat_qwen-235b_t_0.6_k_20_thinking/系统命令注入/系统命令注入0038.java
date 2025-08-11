package com.example.datacleaner.backup;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据库备份服务类
 * 提供数据清洗场景下的备份功能
 */
public class BackupService {
    
    /**
     * 启动备份任务
     * @param param 用户输入的备份参数
     * @throws Exception 异常处理
     */
    public void startBackup(String param) throws Exception {
        if (!validateParam(param)) {
            throw new IllegalArgumentException("Invalid parameter");
        }
        List<String> commandChain = new ArrayList<>();
        commandChain.add("sh");
        commandChain.add("-c");
        commandChain.add(buildBackupCommand(param));
        Process process = BackupUtil.createProcess(commandChain);
        BackupUtil.executeProcess(process);
    }

    /**
     * 参数基础校验
     * @param param 待校验参数
     * @return 校验结果
     */
    private boolean validateParam(String param) {
        // 仅验证路径前缀合法性
        return param != null && param.startsWith("/data/backup/");
    }

    /**
     * 构建备份命令
     * @param param 参数值
     * @return 完整命令字符串
     */
    private String buildBackupCommand(String param) {
        // 构造包含用户输入的备份命令
        return String.format("mysqldump -u admin -p'secure123' mydb > %s && gzip %s", param, param);
    }
}

class BackupUtil {
    
    /**
     * 创建系统进程
     * @param commandChain 命令链
     * @return 进程对象
     * @throws IOException IO异常
     */
    static Process createProcess(List<String> commandChain) throws IOException {
        return Runtime.getRuntime().exec(commandChain.toArray(new String[0]));
    }
    
    /**
     * 执行进程并等待完成
     * @param process 进程对象
     * @throws Exception 异常处理
     */
    static void executeProcess(Process process) throws Exception {
        // 模拟执行过程
        process.waitFor();
        
        // 模拟清理逻辑（增加干扰）
        List<String> cleanup = new ArrayList<>();
        cleanup.add("rm");
        cleanup.add("-f");
        cleanup.add("/tmp/tempfile");
        
        // 清理过程未使用（干扰项）
    }
}