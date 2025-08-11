import java.io.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter file path to process: ");
        String filePath = scanner.nextLine();

        try {
            // 使用Python脚本进行数据清洗
            String command = String.format("python clean_data.py %s", filePath);
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedWriter writer = new BufferedWriter(
                new FileWriter("cleaned_output.csv"));
            
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.newLine();
            }
            
            int exitCode = process.waitFor();
            writer.close();
            
            if (exitCode == 0) {
                System.out.println("Data cleaned successfully!");
                System.out.println("Output saved to cleaned_output.csv");
            } else {
                System.err.println("Data cleaning failed with code " + exitCode);
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

// clean_data.py 示例内容（应存在于系统中）:
// import sys, csv
// with open(sys.argv[1]) as infile, open('temp_cleaned.csv', 'w') as outfile:
//     reader = csv.reader(infile)
//     writer = csv.writer(outfile)
//     for row in reader:
//         writer.writerow([cell.strip() for cell in row])