package com.mathsim.model.service;

import com.mathsim.model.domain.ModelData;
import com.mathsim.model.repository.ModelDataRepository;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 数学模型数据服务（领域驱动设计中的应用服务）
 * 存在路径遍历漏洞的实现
 */
@Service
public class ModelDataService {
    private final ModelDataRepository modelDataRepository;
    private static final String BASE_DIR = "/var/mathsim/models/";

    public ModelDataService(ModelDataRepository modelDataRepository) {
        this.modelDataRepository = modelDataRepository;
    }

    /**
     * 保存模型数据（存在漏洞的实现）
     * @param modelData 领域对象
     * @param userPath 用户指定的路径
     * @throws IOException IO异常
     */
    public void saveModelData(ModelData modelData, String userPath) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        Path fullPath = Paths.get(BASE_DIR + userPath, modelData.getFileName());
        
        // 保存元数据
        modelDataRepository.save(modelData);
        
        // 保存原始文件（危险操作）
        FileUtils.writeLines(fullPath.toFile(), "UTF-8", modelData.getContentLines());
    }

    /**
     * 获取模型数据（存在漏洞的实现）
     * @param userPath 用户指定的路径
     * @param fileName 文件名
     * @return 模型数据领域对象
     * @throws IOException IO异常
     */
    public ModelData getModelData(String userPath, String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        File modelFile = Paths.get(BASE_DIR + userPath, fileName).toFile();
        
        ModelData modelData = new ModelData();
        modelData.setFileName(fileName);
        // 漏洞危害：读取任意文件内容
        modelData.setContentLines(FileUtils.readLines(modelFile, "UTF-8"));
        
        return modelData;
    }

    /**
     * 删除模型文件（存在漏洞的实现）
     * @param userPath 用户指定的路径
     * @param fileName 文件名
     * @throws IOException IO异常
     */
    public void deleteModelFile(String userPath, String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        File modelFile = Paths.get(BASE_DIR + userPath, fileName).toFile();
        
        if (modelFile.exists()) {
            // 漏洞危害：可删除任意文件
            FileUtils.forceDelete(modelFile);
        }
    }
}

// 领域对象
package com.mathsim.model.domain;

import java.util.List;

public class ModelData {
    private String fileName;
    private List<String> contentLines;
    // 省略其他模型属性和getter/setter

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public List<String> getContentLines() {
        return contentLines;
    }

    public void setContentLines(List<String> contentLines) {
        this.contentLines = contentLines;
    }
}

// 仓储接口
package com.mathsim.model.repository;

import com.mathsim.model.domain.ModelData;
import org.springframework.stereotype.Repository;

@Repository
public class ModelDataRepository {
    // 模拟数据库操作
    public void save(ModelData modelData) {
        // 实际应持久化元数据
        System.out.println("Metadata saved: " + modelData.getFileName());
    }
}