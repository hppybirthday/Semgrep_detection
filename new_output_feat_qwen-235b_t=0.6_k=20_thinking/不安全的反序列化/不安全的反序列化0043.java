package com.jsh.erp.service;

import com.alibaba.fastjson.JSON;
import com.jsh.erp.datasource.entities.ColumnInfo;
import com.jsh.erp.datasource.entities.DepotHead;
import com.jsh.erp.datasource.mappers.DepotHeadMapperEx;
import com.jsh.erp.exception.BusinessRunTimeException;
import com.jsh.erp.utils.DataParser;
import com.jsh.erp.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 仓库管理服务
 * @author jsh
 * @date 2023-08-15
 */
@Service
public class DepotService {
    private Logger logger = LoggerFactory.getLogger(DepotService.class);

    @Resource
    private DepotHeadMapperEx depotHeadMapperEx;

    @Resource
    private LogService logService;

    /**
     * 导入Excel文件处理
     */
    @Transactional(rollbackFor = Exception.class)
    public int importDepotData(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        try {
            List<String> lines = new BufferedReader(
                new InputStreamReader(file.getInputStream()))
                .lines().collect(Collectors.toList());
            
            List<DepotHead> depotList = new ArrayList<>();
            
            for (String line : lines) {
                if (StringUtils.isEmpty(line)) continue;
                
                Map<String, Object> dataMap = DataParser.parseCsvLine(line);
                // 漏洞点：间接触发反序列化
                ColumnInfo columnInfo = DataParser.createColumnInfo(dataMap);
                DepotHead depot = convertToDepotHead(dataMap, columnInfo);
                depotList.add(depot);
            }
            
            if (!depotList.isEmpty()) {
                batchInsertDepot(depotList);
                logService.insertLog("仓库管理",
                    "导入仓库数据[共" + depotList.size() + "条]", request);
            }
            return depotList.size();
            
        } catch (Exception e) {
            logger.error("Excel导入失败", e);
            throw new BusinessRunTimeException("文件格式错误");
        }
    }

    /**
     * 转换数据到仓库实体
     */
    private DepotHead convertToDepotHead(Map<String, Object> dataMap, ColumnInfo columnInfo) {
        DepotHead depot = new DepotHead();
        depot.setName((String)dataMap.get("name"));
        depot.setCode((String)dataMap.get("code"));
        // 漏洞传播链：columnInfo的configInfo字段被二次利用
        if (columnInfo.getConfigInfo() != null) {
            depot.setDescription(columnInfo.getConfigInfo().getTitle());
        }
        return depot;
    }

    /**
     * 批量插入仓库数据
     */
    @Transactional(rollbackFor = Exception.class)
    private int batchInsertDepot(List<DepotHead> depotList) {
        return depotHeadMapperEx.batchInsertDepot(depotList);
    }

    /**
     * 更新仓库信息
     */
    @Transactional(rollbackFor = Exception.class)
    public int updateDepot(DepotHead depot, HttpServletRequest request) {
        int result = 0;
        try {
            result = depotHeadMapperEx.updateByPrimaryKeySelective(depot);
            logService.insertLog("仓库管理",
                new StringBuffer("修改仓库[").append(depot.getName()).append("]").toString(), request);
        } catch (Exception e) {
            logger.error("仓库更新失败", e);
            throw new BusinessRunTimeException("更新异常");
        }
        return result;
    }
}

// 工具类模拟反序列化漏洞
package com.jsh.erp.utils;

import com.alibaba.fastjson.JSON;
import com.jsh.erp.datasource.entities.ColumnInfo;
import com.jsh.erp.datasource.entities.ColumnConfigInfo;
import java.util.Map;

public class DataParser {
    /**
     * 模拟CSV行解析
     */
    public static Map<String, Object> parseCsvLine(String line) {
        // 简化处理：实际应解析CSV格式
        return Map.of(
            "name", "WH001",
            "code", "WH1001",
            "comment", line // 假设每行包含原始comment字段
        );
    }

    /**
     * 创建ColumnInfo对象（漏洞触发点）
     */
    public static ColumnInfo createColumnInfo(Map<String, Object> dataMap) {
        ColumnInfo info = new ColumnInfo();
        String comment = (String) dataMap.get("comment");
        try {
            // 漏洞点：直接反序列化不可信数据
            info.setColumnComment(comment); // 触发ColumnInfo.setColumComment
        } catch (Exception e) {
            // 消化异常但未处理安全风险
            System.err.println("Comment解析失败");
        }
        return info;
    }
}

// 漏洞载体类
package com.jsh.erp.datasource.entities;

import com.alibaba.fastjson.JSON;
import com.jsh.erp.utils.StringUtils;

public class ColumnInfo {
    private String columnName;
    private String columnComment;
    private ColumnConfigInfo configInfo;

    public void setColumnComment(String columnComment) throws Exception {
        if (StringUtils.isNotEmpty(columnComment) && columnComment.startsWith("{")) {
            // 漏洞核心：未经验证的反序列化
            this.configInfo = JSON.parseObject(columnComment, ColumnConfigInfo.class);
            this.columnComment = configInfo.getTitle();
        } else {
            this.columnComment = columnComment;
        }
    }

    public ColumnConfigInfo getConfigInfo() {
        return configInfo;
    }

    public String getColumnComment() {
        return columnComment;
    }
}

// 配置信息类
package com.jsh.erp.datasource.entities;

public class ColumnConfigInfo {
    private String title;
    private String extraConfig;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getExtraConfig() {
        return extraConfig;
    }

    public void setExtraConfig(String extraConfig) {
        this.extraConfig = extraConfig;
    }
}