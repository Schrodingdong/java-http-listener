package com.schrodingdong.listener;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.schrodingdong.util.GitHubWebhookValidator;
import com.sun.jdi.InternalException;
import com.sun.net.httpserver.Headers;

public class GithubWebhookHandler implements HttpHandler{
    private final ObjectMapper mapper;
    private final String SECRET_TOKEN = System.getenv("SECRET_TOKEN");
    private final int SUCCESS_STATUS_CODE = 200;
    private final int ERROR_STATUS_CODE = 500;
    private final int FORBIDDEN_STATUS_CODE = 403;
    private final Logger logger;

    public GithubWebhookHandler(){
        this.mapper = new ObjectMapper();
        this.logger = LoggerFactory.getLogger(GithubWebhookHandler.class);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try{
            // Get Request body
            byte[] requestBodyBytes = null;
            try{
                requestBodyBytes = readRequestBodyBytes(exchange);
            } catch(IOException e){
                String error = "Error Reading request Body";
                exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                exchange.getResponseBody().write(error.getBytes());
                throw e;
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
                throw e; 
            }
            if(!isWorkflowCompleteSuccess){
                String error = "Not workflow_run.completed, abort.";
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
                throw e; 
            }

            // All good, execute logic
            try {
                long pid = doLogicInProcesss();
                logger.info("Started sub-process, of pid: " + Long.toString(pid));
                exchange.sendResponseHeaders(SUCCESS_STATUS_CODE, -1);
            } catch (Exception e) {
                String error = "Error executing script";
                exchange.sendResponseHeaders(ERROR_STATUS_CODE, error.length());
                exchange.getResponseBody().write(error.getBytes());
                throw e; 
            }
        } catch(Exception e){
            logger.error(e.getMessage(), e);
        } finally {
            exchange.close();
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


    private byte[] readRequestBodyBytes(HttpExchange exchange) throws IOException, OutOfMemoryError{
        return exchange.getRequestBody().readAllBytes();
    }

    private long doLogicInProcesss() throws Exception{
        String[] cmdArray = {"./script.sh"};
        Process p = Runtime.getRuntime().exec(cmdArray);
        return p.pid();
    } 
}
