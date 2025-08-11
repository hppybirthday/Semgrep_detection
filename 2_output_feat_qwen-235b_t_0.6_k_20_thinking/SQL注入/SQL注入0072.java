package com.example.filesecurity.service;

import com.example.filesecurity.model.FileRecord;
import org.beetl.sql.core.mapper.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 文件记录查询服务
 * 处理文件信息检索与权限验证
 */
@Service
public class FileQueryService {
    @Autowired
    private FileRecordMapper fileRecordMapper;

    /**
     * 根据文件名和类型查询记录
     * @param fileName 文件名称
     * @param fileType 文件类型
     * @return 匹配的文件记录列表
     */
    public List<FileRecord> queryFiles(String fileName, String fileType) {
        Map<String, Object> params = new HashMap<>();
        
        // 构建查询条件
        if (fileName != null && !fileName.isEmpty()) {
            params.put("fileName", "%'" + fileName + "'%");
        }
        
        if (fileType != null && !fileType.isEmpty()) {
            params.put("fileType", fileType);
        }
        
        // 执行安全查询
        return fileRecordMapper.searchFiles(params);
    }
}

interface FileRecordMapper extends Mapper<FileRecord> {
    /**
     * 动态构建SQL查询
     * @param params 查询参数
     * @return 文件记录列表
     */
    List<FileRecord> searchFiles(Map<String, Object> params);
}

/* XML映射文件内容（片段） */
/*
<select id="searchFiles">
    SELECT * FROM file_records
    WHERE 1=1
    <if test="fileName != null">
        AND file_name LIKE ${fileName}
    </if>
    <if test="fileType != null">
        AND file_type = ${fileType}
    </if>
</select>
*/