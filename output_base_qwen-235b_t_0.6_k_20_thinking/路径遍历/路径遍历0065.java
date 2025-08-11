import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

public class VulnerableWebCrawler {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java VulnerableWebCrawler <targetUrl> <outputDir>");
            return;
        }

        String targetUrl = args[0];
        String outputDir = args[1];

        Class<?> handlerClass = createDynamicHandler();
        Object handlerInstance = handlerClass.getConstructor(String.class).newInstance(outputDir);
        
        Method processMethod = handlerClass.getMethod("processUrl", String.class);
        processMethod.invoke(handlerInstance, targetUrl);
    }

    private static Class<?> createDynamicHandler() throws Exception {
        String className = "DynamicContentHandler";
        String srcCode = "import java.io.*;import java.net.*;public class " + className + " {" +
            "private String baseDir;" +
            "public " + className + "(String dir){baseDir=dir;}" +
            "public void processUrl(String urlStr) throws Exception{" +
            "URL url = new URL(urlStr);" +
            "String path = url.getPath().replaceAll("\\"/\\+\\"", "\\"/\\"");" +
            "String filename = baseDir + "/" + path.replaceFirst("\\".*?/\\+\\"", "\\"\\"");" +
            "File file = new File(filename);" +
            "if(!file.getCanonicalPath().startsWith(new File(baseDir).getCanonicalPath())){" +
            "throw new SecurityException(\\"Invalid path traversal attempt\\");}" +
            "file.getParentFile().mkdirs();" +
            "try(InputStream in = url.openStream();" +
            "FileOutputStream out = new FileOutputStream(file)){" +
            "byte[] buffer = new byte[4096];int len;" +
            "while((len=in.read(buffer))>0){out.write(buffer,0,len);}" +
            "System.out.println(\\"Saved to \\" + filename);}" +
            "}" +
            "}";

        Path tempDir = Files.createTempDirectory("dynamic");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        Path sourceFile = tempDir.resolve(className + ".java");
        Files.write(sourceFile, srcCode.getBytes());

        compiler.run(null, null, null, sourceFile.toString());
        URLClassLoader classLoader = URLClassLoader.newInstance(
            new URL[]{tempDir.toUri().toURL()});

        return Class.forName(className, true, classLoader);
    }
}