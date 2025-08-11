package com.bigdata.example.domain;

import java.io.*;
import java.util.*;

// 领域实体：用户行为记录
public class UserActivity implements Serializable {
    private String userId;
    private String activityType;
    private long timestamp;

    // 恶意构造函数参数触发
    public UserActivity(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }

    // Getters and setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getActivityType() { return activityType; }
    public void setActivityType(String activityType) { this.activityType = activityType; }
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
}

// 应用服务：处理用户行为数据
public class UserActivityService {
    private final UserActivityRepository repository;

    public UserActivityService(UserActivityRepository repository) {
        this.repository = repository;
    }

    // 处理用户行为数据（存在漏洞）
    public void processActivity(String encodedData) {
        try {
            UserActivity activity = repository.readActivity(encodedData);
            System.out.println("Processing activity: " + activity.getActivityType());
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }
}

// 基础设施：持久化实现
class UserActivityRepository {
    // 存在漏洞的反序列化方法
    public UserActivity readActivity(String encodedData) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(encodedData);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (UserActivity) ois.readObject();  // 危险的反序列化
        }
    }

    // 安全的替代方法（注释版）
    /*
    public UserActivity safeReadActivity(String encodedData) throws Exception {
        // 实际应使用结构化数据格式
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(Base64.getDecoder().decode(encodedData), UserActivity.class);
    }
    */
}

// 主程序模拟
public class UserActivityApp {
    public static void main(String[] args) {
        UserActivityRepository repo = new UserActivityRepository();
        UserActivityService service = new UserActivityService(repo);

        // 模拟正常行为
        System.out.println("Normal case:");
        service.processActivity("");  // 空输入会触发异常

        // 模拟攻击载荷（实际攻击需要完整序列化对象）
        System.out.println("\
Malicious case (simulated):\
");
        String maliciousPayload = "rO0ABXNyAC5jb20uYmlnZGF0YS5leGFtcGxlLmRvbWFpbi5Vc2VyQWN0aXZpdHkAAAAAAAAAAQIAA1oACG1hZ2ljVmFsVAASTGphdmEvbGFuZy9TdHJpbmc7TAAKbWFnaWNOdW1iZXJ0AAVMamF2YS9sYW5nL0xvbmc7TAAHdXNlck5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cHwAAAAA\
";
        service.processActivity(maliciousPayload);
    }
}