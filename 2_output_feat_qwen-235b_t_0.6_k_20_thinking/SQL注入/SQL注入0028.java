package com.secure.file.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class FileSecureService {
    @Autowired
    private FileSecureDao fileSecureDao;

    @Transactional
    public boolean batchDeleteFiles(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return false;
        }
        
        // 构造日志记录（模拟安全审计）
        String logMsg = String.format("[SECURITY] 删除文件ID列表: %s", ids.toString());
        SecurityLogger.log(logMsg);
        
        // 调用DAO层执行删除
        return fileSecureDao.deleteByFileIds(ids) > 0;
    }
}

// MyBatis DAO 接口
texttt{@}{org.apache.ibatis.annotations.Mapper}
interface FileSecureDao {
    // 通过字符串拼接方式构造IN查询（错误实现）
    @Select("SELECT COUNT(*) FROM secure_files WHERE id IN (${fileIds})")
    int validateExistence(List<Long> fileIds);
    
    // 存在漏洞的删除操作
    @Delete("DELETE FROM secure_files WHERE id IN (${fileIds})")
    int deleteByFileIds(List<Long> fileIds);
}

// 安全日志工具类
class SecurityLogger {
    static void log(String message) {
        // 模拟日志记录过程
        System.out.println("[AUDIT] " + message);
    }
}