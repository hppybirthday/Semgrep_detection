package com.gamestudio.archive;

import java.io.IOException;

// 领域实体
class GameArchive {
    private String archiveId;
    private String archiveName;

    public GameArchive(String archiveId, String archiveName) {
        this.archiveId = archiveId;
        this.archiveName = archiveName;
    }

    public String getArchiveName() {
        return archiveName;
    }
}

// 应用服务
class ArchiveService {
    public void backupArchive(GameArchive archive) {
        String archiveName = archive.getArchiveName();
        // 漏洞点：直接拼接用户输入到系统命令
        String command = "zip -r game_backup_" + archiveName + ".zip game_data/" + archiveName;
        
        try {
            // 使用Runtime.exec()执行命令
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 基础设施
class ExternalCommandExecutor {
    public void executeCommand(String cmd) {
        try {
            // 漏洞延续点：直接执行传入的命令字符串
            Runtime.getRuntime().exec("cmd.exe /c " + cmd);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 仓储接口
interface ArchiveRepository {
    GameArchive findArchiveById(String id);
}

// 测试类
public class GameBackupCLI {
    public static void main(String[] args) {
        ArchiveService archiveService = new ArchiveService();
        ExternalCommandExecutor executor = new ExternalCommandExecutor();
        
        System.out.println("=== 游戏存档备份系统 ===");
        System.out.print("请输入存档名称: ");
        
        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
            String archiveName = scanner.nextLine();
            
            // 创建存档对象
            GameArchive archive = new GameArchive("123", archiveName);
            
            // 执行备份操作
            archiveService.backupArchive(archive);
            
            // 模拟其他命令执行
            System.out.print("输入调试命令: ");
            String debugCmd = scanner.nextLine();
            executor.executeCommand(debugCmd);
        }
    }
}