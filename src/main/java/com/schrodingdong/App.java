package com.schrodingdong;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


import com.sun.net.httpserver.*;
public class App 
{
    static final String USAGE_MESSAGE = """
            usage:
                java -jar github-webhook-listener <HOST> <PORT>
            """;
            
    public static void main(String[] args){
        if(args.length != 2){
            System.err.println("Wrong Argument length provided");
            System.err.println(USAGE_MESSAGE);
        }

        String host = "";
        int port = 0;
        try{
            host = args[0];
            port = Integer.parseInt(args[1]);
        } catch(Exception e){
            System.err.println("Error parsing arguments");
            System.err.println(USAGE_MESSAGE);
        }

        // Create server listener
        MyListener listener = new MyListener(host, port);
        listener.startListener();
    }
}


class MyListener {
    private final String SECRET_TOKEN = System.getenv("SECRET_TOKEN");
    private final int SUCCESS_STATUS_CODE = 200;
    private final int ERROR_STATUS_CODE = 500;
    private final int FORBIDDEN_STATUS_CODE = 403;
    private HttpServer listener;
    private String IP;
    private int port;

    public MyListener(String IP, int port){
        this.IP = IP;
        this.port = port;
        try {
            this.listener = HttpServer.create(new InetSocketAddress(port), 0);
            listener.createContext("/gh-webhook-listener", (exchange) -> {
                try{
                    // Get Request body
                    byte[] requestBodyRaw = null;
                    try{
                        requestBodyRaw = readRequestBody(exchange);
                    } catch(IOException e){
                        System.err.println("Error Reading request Body");
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, -1);
                        return;
                    }
                    
                    // Get Heaeder Hash
                    Headers headers = exchange.getRequestHeaders();
                    String requestHash = headers.getFirst("X-Hub-Signature-256");
                    if(requestHash == "" || requestHash.isEmpty()){
                        System.err.println("No header 'X-Hub-Signature-256' present in the incomming request.");
                        exchange.sendResponseHeaders(FORBIDDEN_STATUS_CODE, -1);
                        return;
                    }

                    // Calculate Body Hash
                    String bodyHash = "";
                    try {
                        bodyHash = "sha256=" + calculateHMAC(requestBodyRaw, SECRET_TOKEN);
                    } catch (NoSuchAlgorithmException e) {
                        System.err.println("No such algorithm");
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, -1);
                        return;
                    } catch(InvalidKeyException e) {
                        System.err.println("Invalid Key");
                        exchange.sendResponseHeaders(port, port);
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, -1);
                        return;
                    }

                    // Verify Hash
                    if(!requestHash.equals(bodyHash)){
                        System.err.println("Different hashes:");
                        System.err.println(requestHash);
                        System.err.println(bodyHash);
                        exchange.sendResponseHeaders(FORBIDDEN_STATUS_CODE, -1);
                        return;
                    }

                    // All good, execute logic
                    doLogic();
                    exchange.sendResponseHeaders(SUCCESS_STATUS_CODE, -1);
                } finally {
                    exchange.close();
                }
            });
        } catch(Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void startListener(){
        System.err.println(String.format("Start Listner on %s:%d", IP, port));
        listener.setExecutor(null); // creates a default executor
        listener.start();
    }

    private static String calculateHMAC(byte[] data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secretKey);

        // Compute the HMAC for the payload
        byte[] hmacData = sha256_HMAC.doFinal(data);

        // Convert the HMAC to a hexadecimal string
        return bytesToHex(hmacData);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private byte[] readRequestBody(HttpExchange exchange) throws IOException, OutOfMemoryError{
        InputStream is = exchange.getRequestBody();
        return is.readAllBytes();
    }


    private String doLogic(){
        String[] cmdArray = {"./script.sh"};
        try{
            Process p =  Runtime.getRuntime().exec(cmdArray);
            p.waitFor();
            InputStream stream = p.getInputStream();
            String out = "";
            while(stream.available() != 0){
                out += (char) stream.read();
            }
            return "Script executed successfully: " + out;
        } catch(Exception e) {
            return "Error Executing the script: " + e.getMessage();
        }
    } 
}
