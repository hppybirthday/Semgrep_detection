import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class FileEncryptor {
    private static final byte KEY = (byte) 0xA5;

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: java FileEncryptor <encrypt|decrypt> <input_path> <output_path>");
            return;
        }

        String operation = args[0];
        File inputFile = new File(args[1]);
        File outputFile = new File(args[2]);

        try {
            if (operation.equals("encrypt")) {
                encryptFile(inputFile, outputFile);
            } else if (operation.equals("decrypt")) {
                decryptFile(inputFile, outputFile);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error during file processing: " + e.getMessage());
        }
    }

    private static void encryptFile(File source, File target) throws IOException {
        try (InputStream in = new FileInputStream(source);
             OutputStream out = new FileOutputStream(target)) {
            int data;
            while ((data = in.read()) != -1) {
                out.write(data ^ KEY);
            }
        }
    }

    private static void decryptFile(File source, File target) throws IOException {
        try (InputStream in = new FileInputStream(source);
             OutputStream out = new FileOutputStream(target)) {
            int data;
            while ((data = in.read()) != -1) {
                out.write(data ^ KEY);
            }
        }
    }

    private static boolean isSafePath(String path) {
        // 错误的安全验证，仅检查前缀而非实际路径
        return path.startsWith("./") || path.startsWith("../");
    }
}