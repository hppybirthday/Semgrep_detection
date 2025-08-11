import java.io.*;
import java.nio.file.*;
import java.util.*;

public class TaskManager {
    private String storagePath;

    public TaskManager(String storagePath) {
        this.storagePath = storagePath;
    }

    public byte[] retrieveTaskFile(String userProvidedPath) throws IOException {
        File targetFile = new File(storagePath + userProvidedPath);
        System.out.println("Accessing file: " + targetFile.getAbsolutePath());
        return Files.readAllBytes(targetFile.toPath());
    }

    public void registerTask(Task task) {
        System.out.println("Registering task: " + task.getId());
    }

    public static void main(String[] args) {
        TaskManager manager = new TaskManager("/opt/app/tasks/");
        try {
            String userInput = "../../../../etc/passwd";
            if (args.length > 0) {
                userInput = args[0];
            }
            System.out.println("File name: " + FileManager.getFileName(userInput));
            byte[] data = manager.retrieveTaskFile(userInput);
            System.out.println("File content size: " + data.length);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

class Task {
    private String id;
    private String description;
    private String attachmentPath;

    public Task(String id, String description, String attachmentPath) {
        this.id = id;
        this.description = description;
        this.attachmentPath = attachmentPath;
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }

    public String getAttachmentPath() {
        return attachmentPath;
    }
}

class FileManager {
    public static String getFileName(String path) {
        int lastSlash = path.lastIndexOf('/');
        return path.substring(lastSlash + 1);
    }
}