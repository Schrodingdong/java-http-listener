package com.schrodingdong.listener;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpServer;

public class GithubWebhookListener {
    private HttpServer listener;
    private int port;
    private final Logger logger;

    public GithubWebhookListener(int port){
        this.logger = LoggerFactory.getLogger(GithubWebhookListener.class);
        this.port = port;
        try {
            this.listener = HttpServer.create(new InetSocketAddress(port), 0);
            listener.createContext("/gh-webhook-listener", new GithubWebhookHandler());
        } catch(Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    public void startListener(){
        System.out.println(String.format("Start Listner on port %d ...", port));
        listener.setExecutor(null); // creates a default executor
        listener.start();
    }
}
