package com.schrodingdong;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.schrodingdong.util.GitHubWebhookValidator;
import com.sun.jdi.InternalException;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
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
        System.out.println(args.length); 
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
            if(debugArg.toUpperCase().equals("TRUE"))
                debug = true;
            System.out.println("Debug set to TRUE");
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
    private final ObjectMapper mapper;

    public MyListener(int port, boolean debug){
        this.mapper = new ObjectMapper();
        this.port = port;
        this.debug = debug;
        try {
            this.listener = HttpServer.create(new InetSocketAddress(port), 0);
            listener.createContext("/gh-webhook-listener", (exchange) -> {
                try{
                    // Get Request body
                    byte[] requestBodyBytes = null;
                    try{
                        requestBodyBytes = readRequestBodyBytes(exchange);
                    } catch(IOException e){
                        String error = "Error Reading request Body";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }
                    String requestBodyRequest = new String(requestBodyBytes);


                    // Ensure the request is a successful completed workflow
                    boolean isWorkflowCompleteSuccess = false;
                    try {
                        isWorkflowCompleteSuccess = isWorkflowCompleteSuccess(requestBodyRequest);
                    } catch (InternalError e) {
                        String error = e.getMessage();
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }
                    if(!isWorkflowCompleteSuccess){
                        String error = "Not workflow_run.completed";
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }

                    
                    // Get Header Hash
                    Headers headers = exchange.getRequestHeaders();
                    String requestHash = headers.getFirst("X-Hub-Signature-256");
                    if(requestHash.isBlank() || requestHash == null){
                        String error = "No header 'X-Hub-Signature-256' present in the incomming request.";
                        exchange.sendResponseHeaders(FORBIDDEN_STATUS_CODE, error.length());
                        exchange.getResponseBody().write(error.getBytes());
                        throw new Exception(error);
                    }

                    // Calculate Body Hash
                    try {
                        GitHubWebhookValidator.validateGitHubWebhook(
                            requestBodyBytes, 
                            SECRET_TOKEN, 
                            requestHash
                        );
                    } catch (SecurityException e) {
                        String error = "Error validating hash: " + e.getMessage();
                        exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
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

    private boolean isWorkflowCompleteSuccess(String bodyString) throws InternalException {
        // Parse to JSON
        JsonNode bodyNode = null;
        try {
            bodyNode = mapper.readTree(bodyString);
        } catch (Exception e) {
            String err = "Error Mapping body to JSON";
            throw new InternalException(err);
        }

        // Get payload values
        String action = "";
        String conclusion = "";
        try {
            action = bodyNode.get("action").textValue();
            conclusion = bodyNode.get("workflow_run").get("conclusion").textValue();
        } catch (Exception e) {
            String err = e.getMessage();
            throw new InternalException(err);
        }
        if(action == null || conclusion == null) 
            return false;
        return action.equals("completed") && conclusion.equals("success");
    }

    public void startListener(){
        System.err.println(String.format("Start Listner on port %d ...", port));
        listener.setExecutor(null); // creates a default executor
        listener.start();
    }

    private static String calculateHMAC(String data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secretKey);

        // Compute the HMAC for the payload
        byte[] hmacData = sha256_HMAC.doFinal(data.getBytes());

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

    private byte[] readRequestBodyBytes(HttpExchange exchange) throws IOException, OutOfMemoryError{
        return exchange.getRequestBody().readAllBytes();
    }


    private long doLogicInProcesss() throws Exception{
        String[] cmdArray = {"./script.sh"};
        Process p = Runtime.getRuntime().exec(cmdArray);
        return p.pid();
    } 
}
