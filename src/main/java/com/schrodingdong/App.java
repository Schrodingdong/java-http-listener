package com.schrodingdong;

import java.net.InetSocketAddress;

import com.schrodingdong.handler.GithubWebhookListener;
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
    private HttpServer listener;
    private int port;

    public MyListener(int port, boolean debug){
        this.port = port;
        try {
            this.listener = HttpServer.create(new InetSocketAddress(port), 0);
            listener.createContext("/gh-webhook-listener", new GithubWebhookListener(debug));
        } catch(Exception e) {
            System.out.println(e.getMessage());
            if(debug)
                e.printStackTrace();
        }
    }

    public void startListener(){
        System.out.println(String.format("Start Listner on port %d ...", port));
        listener.setExecutor(null); // creates a default executor
        listener.start();
    }

}
