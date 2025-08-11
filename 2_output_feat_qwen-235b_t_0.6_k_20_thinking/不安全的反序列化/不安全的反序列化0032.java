package com.example.dataprocessor.cleaner;

import com.alibaba.fastjson.JSON;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 数据清洗处理器
 * 处理用户上传的Excel文件进行数据清洗转换
 */
public class DataCleaner {
    /**
     * 清洗Excel数据并转换为业务对象
     * @param fileData Base64编码的Excel文件数据
     * @return 清洗后的业务数据集合
     */
    public List<BusinessData> processExcelData(String fileData) {
        try (InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(fileData));
             Workbook workbook = new XSSFWorkbook(is)) {

            Sheet sheet = workbook.getSheetAt(0);
            return sheet.stream()
                .map(this::validateRow)
                .filter(this::isValidFormat)
                .map(this::convertToBusinessData)
                .collect(Collectors.toList());

        } catch (Exception e) {
            // 记录日志并返回空集合
            return List.of();
        }
    }

    /**
     * 验证并转换数据行
     */
    private Row validateRow(Row row) {
        // 简单校验行格式
        if (row.getLastCellNum() < 3) {
            throw new IllegalArgumentException("Invalid row format");
        }
        return row;
    }

    /**
     * 检查数据格式有效性
     */
    private boolean isValidFormat(Row row) {
        // 校验第一个单元格为数字格式
        Cell cell = row.getCell(0);
        return cell != null && cell.getCellType() == Cell.CELL_TYPE_NUMERIC;
    }

    /**
     * 将数据行转换为业务对象
     */
    private BusinessData convertToBusinessData(Row row) {
        // 获取第三个单元格的扩展配置数据
        Cell configCell = row.getCell(2);
        String configJson = configCell.getStringCellValue();
        
        // 将JSON配置反序列化为业务对象
        Map<String, Object> configMap = JSON.parseObject(configJson, Map.class);
        return new BusinessData(
            row.getCell(0).getNumericCellValue(),
            row.getCell(1).getStringCellValue(),
            parseExtendedConfig(configMap)
        );
    }

    /**
     * 解析扩展配置数据
     */
    private ExtendedConfig parseExtendedConfig(Map<String, Object> configMap) {
        // 存在潜在风险的反序列化操作
        String configType = (String) configMap.get("type");
        String configValue = (String) configMap.get("value");
        
        // 根据配置类型动态反序列化
        if ("advanced".equals(configType)) {
            // 危险的反序列化操作
            return JSON.parseObject(configValue, ExtendedConfig.class);
        }
        
        return new BasicConfig();
    }
}

/**
 * 业务数据基类
 */
abstract class BusinessData {
    public BusinessData(double id, String name, ExtendedConfig config) {
        // 初始化公共字段
    }
}

/**
 * 扩展配置基类
 */
abstract class ExtendedConfig {
    public void validate() {
        // 基础校验逻辑
    }
}

/**
 * 基础配置实现类
 */
class BasicConfig extends ExtendedConfig {
    @Override
    public void validate() {
        super.validate();
    }
}