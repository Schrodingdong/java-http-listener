package com.schrodingdong;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

import javax.crypto.Cipher;

import com.sun.net.httpserver.*;
public class App 
{
    public static void main(String[] args){
        // Create server listener
        MyListener listener = new MyListener("localhost", 8888);
        listener.startListener();
    }
}


@SuppressWarnings("restriction")
class MyListener {
    private final String HARDCODED_TOKEN = System.getenv("SECRET_TOKEN");
    private HttpServer listener;
    private String IP;
    private int port;

    public MyListener(String IP, int port){
        this.IP = IP;
        this.port = port;
        try {
            this.listener = HttpServer.create(new InetSocketAddress(port), 0);
            listener.createContext("/", (exchange) -> {
                // Check for token
                String token = exchange.getRequestHeaders().getFirst("token");

                // Do logic if we have token
                String result = ""; 
                if(token.equals(HARDCODED_TOKEN)){
                    result = doLogic();
                    exchange.sendResponseHeaders(200, result.length());
                } else {
                    result = "Wrong token";
                    exchange.sendResponseHeaders(401, result.length());
                }
                // Return result
                OutputStream reqBodyOutputStream =  exchange.getResponseBody();
                reqBodyOutputStream.write(result.getBytes());
                exchange.close();
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

    private String doLogic(){
        String[] cmdArray = {"script.sh"};
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

