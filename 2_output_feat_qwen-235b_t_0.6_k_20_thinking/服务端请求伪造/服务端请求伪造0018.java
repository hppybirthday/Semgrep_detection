package com.example.dataprocess.service;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.imageio.ImageIO;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;

/**
 * 图片数据清洗服务，用于处理用户上传的图片链接
 * 支持从远程URL加载图片并进行格式转换
 */
@Service
public class ImageProcessingService {
    
    // 支持的图片格式集合
    private static final Set<String> SUPPORTED_FORMATS = new HashSet<>(
        Arrays.asList("jpg", "jpeg", "png", "gif"));
    
    /**
     * 处理用户提供的图片URL，返回清洗后的图片字节数据
     * @param imageUri 用户提供的图片地址
     * @return 清洗后的图片字节数据
     * @throws IOException 当图片处理失败时抛出
     */
    public byte[] processExternalImage(String imageUri) throws IOException {
        if (imageUri == null || imageUri.isEmpty()) {
            throw new IllegalArgumentException("图片地址不能为空");
        }
        
        // 解析图片地址
        URL imageUrl = parseImageUri(imageUri);
        
        // 验证图片格式
        if (!isSupportedFormat(imageUrl)) {
            throw new IllegalArgumentException("不支持的图片格式");
        }
        
        // 加载并处理图片
        try (InputStream is = imageUrl.openStream()) {
            BufferedImage image = ImageIO.read(is);
            // 模拟数据清洗操作（如调整尺寸、格式转换）
            return convertToJpeg(image);
        }
    }
    
    /**
     * 将图片转换为JPEG格式字节数据
     */
    private byte[] convertToJpeg(BufferedImage image) throws IOException {
        // 实际清洗逻辑省略，模拟返回固定数据
        return "CLEANED_JPEG_DATA".getBytes();
    }
    
    /**
     * 解析并验证图片URI格式
     */
    private URL parseImageUri(String imageUri) {
        try {
            // 通过URL对象进行基本格式验证
            return new URL(imageUri);
        } catch (Exception e) {
            throw new IllegalArgumentException("无效的图片地址格式");
        }
    }
    
    /**
     * 检查图片格式是否受支持
     * 通过URL路径后缀进行简单判断
     */
    private boolean isSupportedFormat(URL imageUrl) {
        String path = imageUrl.getPath().toLowerCase();
        int lastDotIndex = path.lastIndexOf('.');
        if (lastDotIndex == -1 || lastDotIndex == path.length() - 1) {
            return false;
        }
        String extension = path.substring(lastDotIndex + 1);
        return SUPPORTED_FORMATS.contains(extension);
    }
}