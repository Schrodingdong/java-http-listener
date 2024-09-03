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
                java -jar github-webhook-listener <PORT> <DEBUG>
            where:
                PORT  - (long) Port to open to listen to request
                DEBUG - (TRUE or FALSE (default)) Allow errors and stack trace to show 
            """;
            
    public static void main(String[] args){
        if(args.length < 1 || args.length > 2){
            System.err.println("Wrong Argument length provided");
            System.err.println(USAGE_MESSAGE);
            return;
        }

        int port = 0;
        boolean debug = false;
        try{
            port = Integer.parseInt(args[0]);
        } catch(Exception e){
            System.err.println("Error parsing arguments");
            System.err.println(USAGE_MESSAGE);
            return;
        }
        try{
            String debugArg = args[1];
            if(debugArg == "TRUE")
                debug = true;
        } catch(IndexOutOfBoundsException e){
            System.out.println("Debug set to FALSE");
        }

        // Create server listener
        MyListener listener = new MyListener(port, debug);
        listener.startListener();
    }
}


class MyListener {
    private final String SECRET_TOKEN = System.getenv("SECRET_TOKEN");
    private final int SUCCESS_STATUS_CODE = 200;
    private final int ERROR_STATUS_CODE = 500;
    private final int FORBIDDEN_STATUS_CODE = 403;
    private HttpServer listener;
    private int port;
    private boolean debug;

    public MyListener(int port, boolean debug){
        this.port = port;
        this.debug = debug;
        try {
            this.listener = HttpServer.create(new InetSocketAddress(port), 0);
            listener.createContext("/gh-webhook-listener", (exchange) -> {
                try{
                    // Get Request body
                    byte[] requestBodyRaw = null;
                    try{
                        requestBodyRaw = readRequestBody(exchange);
                    } catch(IOException e){
                        String error = "Error Reading request Body";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }
                    
                    // Get Heaeder Hash
                    Headers headers = exchange.getRequestHeaders();
                    String requestHash = headers.getFirst("X-Hub-Signature-256");
                    if(requestHash.isBlank() || requestHash == null){
                        String error = "No header 'X-Hub-Signature-256' present in the incomming request.";
                        exchange.sendResponseHeaders(FORBIDDEN_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }

                    // Calculate Body Hash
                    String bodyHash = "";
                    try {
                        bodyHash = "sha256=" + calculateHMAC(requestBodyRaw, SECRET_TOKEN);
                    } catch (NoSuchAlgorithmException e) {
                        String error = "No such algorithm";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    } catch(InvalidKeyException e) {
                        String error = "Invalid Key";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    } catch(Exception e){
                        String error = "Error calculating hash";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }

                    // Verify Hash
                    if(!requestHash.equals(bodyHash)){
                        String error = "Different hashes";
                        exchange.sendResponseHeaders(FORBIDDEN_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }

                    // All good, execute logic
                    try {
                        long pid = doLogicInProcesss();
                        System.out.println("Started sub-process, of pid: " + Long.toString(pid));
                        exchange.sendResponseHeaders(SUCCESS_STATUS_CODE, -1);
                    } catch (Exception e) {
                        String error = "Error executing script";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }
                } catch(Exception e){
                    System.err.println(e.getMessage());
                    if(debug)
                        e.printStackTrace();
                } finally {
                    exchange.close();
                }
            });
        } catch(Exception e) {
            System.out.println(e.getMessage());
            if(debug)
                e.printStackTrace();
        }
    }

    public void startListener(){
        System.err.println(String.format("Start Listner on port %d ...", port));
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


    private long doLogicInProcesss() throws Exception{
        String[] cmdArray = {"./script.sh"};
        Process p = Runtime.getRuntime().exec(cmdArray);
        return p.pid();
    } 
}
