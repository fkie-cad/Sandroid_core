package de.fkie.ground_truth;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.*;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize the buttons
        Button button1 = findViewById(R.id.button1);
        Button button2 = findViewById(R.id.button2);
        Button button3 = findViewById(R.id.button3);
        Button button4 = findViewById(R.id.button4);
        Button button5 = findViewById(R.id.button5);
        Button button6 = findViewById(R.id.button6);
        Button button7 = findViewById(R.id.button7);
        Button button8 = findViewById(R.id.button8);
        Button button9 = findViewById(R.id.button9);
        Button button10 = findViewById(R.id.button10);

        // Set labels for the buttons
        button1.setText("Create a new file");
        button2.setText("Add Database Entry");
        button3.setText("Delete Database Entry");
        button4.setText("Update Database Entry");
        button5.setText("Send 42 Bytes to 'fkie.fraunhofer.de'");
        button6.setText("Start process 'yes'");
        button7.setText("Add XML Entry");
        button8.setText("Delete XML Entry");
        button9.setText("Update XML Entry");
        button10.setText("Download APK");

        Log.i("DB Debug","Running the Database Helper now.");
        DatabaseHelper db = new DatabaseHelper(this);
        XMLHelper xml = new XMLHelper(this);

        // Add click listeners (you can customize the behavior here)
        button1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                createNewFile();
            }
        });

        button2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long timeStampSeconds = 0;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    Instant instant = Instant.now();
                    timeStampSeconds = instant.getEpochSecond();
                }
                db.insertData(Long.toString(timeStampSeconds));
            }
        });

        button3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                db.deleteData("1");
            }
        });

        button4.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long timeStampSeconds = 0;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    Instant instant = Instant.now();
                    timeStampSeconds = instant.getEpochSecond();
                }
                db.updateData("0", Long.toString(timeStampSeconds));
            }
        });

        button5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendBytes("fkie.fraunhofer.de", 443, 42);
            }
        });

        button6.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.submit(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            button6.setText("Start process 'yes' (running)");
                            Process process = Runtime.getRuntime().exec("yes");
                            Thread.sleep(1500);
                            button6.setText("Start process 'yes'");
                        } catch (IOException | InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                });
                executor.shutdown();
            }
        });

        button7.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long timeStampSeconds = 0;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    Instant instant = Instant.now();
                    timeStampSeconds = instant.getEpochSecond();
                }
                xml.insertData(Long.toString(timeStampSeconds));
            }
        });

        button8.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                xml.deleteData();
            }
        });

        button9.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long timeStampSeconds = 0;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    Instant instant = Instant.now();
                    timeStampSeconds = instant.getEpochSecond();
                }
                xml.updateData(Long.toString(timeStampSeconds));
            }
        });

        button10.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                //TODO download functionality

            }
        });
    }

    private void createNewFile() {
        // Get the app's internal storage directory
        File internalStorageDir = getFilesDir();

        // Find the largest existing numeric file name (if any)
        int largestNumber = findLargestFileNumber(internalStorageDir);

        // Create a new file with the next number
        File newFile = new File(internalStorageDir, "file_" + (largestNumber + 1) + ".txt");

        try {
            // Write some content to the file (optional)
            String fileContent = "Hello, this is my new file!";
            FileOutputStream outputStream = new FileOutputStream(newFile);
            outputStream.write(fileContent.getBytes());
            outputStream.close();

            // Display a message indicating success
            System.out.println("New file created: " + newFile.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
            // Handle any exceptions (e.g., permission issues)
        }
    }

    private int findLargestFileNumber(File directory) {
        int largestNumber = 0;
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    String fileName = file.getName();
                    if (fileName.matches("file_(\\d+)\\.txt")) {
                        int number = Integer.parseInt(fileName.replaceAll("file_(\\d+)\\.txt", "$1"));
                        largestNumber = Math.max(largestNumber, number);
                    }
                }
            }
        }
        return largestNumber;
    }

    public void sendBytes(final String host, final int port, final int numBytes) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(new Runnable() {
            @Override
            public void run() {
                byte[] data = new byte[numBytes];  // Create a byte array of the specified length

                try (Socket socket = new Socket(host, port);
                     OutputStream out = socket.getOutputStream()) {

                    out.write(data);  // Send the bytes
                    out.flush();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        executor.shutdown();
    }


}
