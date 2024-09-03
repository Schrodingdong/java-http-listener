package com.schrodingdong;

import com.schrodingdong.listener.GithubWebhookListener;

public class App 
{
    static final String USAGE_MESSAGE = """
            usage:
                java -jar github-webhook-listener <PORT> 
            where:
                PORT  - (long) Port to open to listen to request
            """;
            
    public static void main(String[] args){
        // Check args
        if(args.length != 1){
            System.err.println("Wrong Argument length provided");
            System.err.println(USAGE_MESSAGE);
            return;
        }

        // Get port from args
        int port = 0;
        try{
            port = Integer.parseInt(args[0]);
        } catch(Exception e){
            System.err.println("Error parsing arguments");
            System.err.println(USAGE_MESSAGE);
            return;
        }

        // Create server listener
        GithubWebhookListener listener = new GithubWebhookListener(port);
        listener.startListener();
    }
}


