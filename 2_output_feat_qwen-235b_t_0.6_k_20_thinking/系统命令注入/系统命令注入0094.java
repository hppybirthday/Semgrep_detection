package com.enterprise.scheduler.handler;

import com.enterprise.core.job.IJobHandler;
import com.enterprise.core.job.JobHandler;
import com.enterprise.core.model.JobResult;
import com.enterprise.core.util.DbUtil;
import com.enterprise.core.model.BackupConfig;
import com.enterprise.core.serializer.JsonParser;
import java.io.BufferedReader;
import java.io.InputStreamReader;

@JobHandler(value = "databaseBackupHandler")
public class BackupJobHandler extends IJobHandler {

    private final DbUtil dbUtil = new DbUtil();

    @Override
    public JobResult execute(String param) {
        try {
            BackupConfig config = JsonParser.parse(param, BackupConfig.class);
            
            if (!validateParams(config)) {
                return JobResult.fail("Invalid configuration parameters");
            }

            String command = dbUtil.buildBackupCommand(
                config.getHost(),
                config.getPort(),
                config.getUser(),
                config.getPassword(),
                config.getDatabase()
            );

            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return JobResult.success(output.toString());
            
        } catch (Exception e) {
            return JobResult.fail("Backup execution failed: " + e.getMessage());
        }
    }

    private boolean validateParams(BackupConfig config) {
        return config != null && 
               config.getHost() != null &&
               config.getPort() > 0 &&
               config.getUser() != null &&
               config.getPassword() != null &&
               config.getDatabase() != null;
    }
}

// --- DbUtil.java ---
package com.enterprise.core.util;

public class DbUtil {
    
    public String buildBackupCommand(String host, int port, 
                                    String user, String password, 
                                    String database) {
        // 构建数据库连接字符串（业务逻辑）
        String connectionString = String.format("jdbc:mysql://%s:%d/%s", 
                                              host, port, database);
        
        // 构建备份命令（业务逻辑）
        return String.format("mysqldump -h %s -P %d -u%s -p%s %s",
                           host, port, user, password, database);
    }
}

// --- BackupConfig.java ---
package com.enterprise.core.model;

public class BackupConfig {
    private String host;
    private int port;
    private String user;
    private String password;
    private String database;
    
    // Getters and setters omitted for brevity
}

// --- JobResult.java ---
package com.enterprise.core.model;

public class JobResult {
    private boolean success;
    private String message;
    
    public static JobResult success(String message) {
        JobResult result = new JobResult();
        result.setSuccess(true);
        result.setMessage(message);
        return result;
    }
    
    public static JobResult fail(String message) {
        JobResult result = new JobResult();
        result.setSuccess(false);
        result.setMessage(message);
        return result;
    }

    // Getters and setters omitted for brevity
}