# Github Webhook Java Client

Simple Java HTTP client listening to webhooks.

## How to use

- Create a `script.sh` in root of project. Upon receiving a webhook request, this script will get executed.
- Give execution permission: `chmod +x script.sh`
- Set a secret token as an ENV variable `SECRET_TOKEN`. This token will be used to hash the request body and verify against the `X-Hub-Signature-256` header.
- Build the mvn application
```sh
mvn clean install
```
- Run the jar
```sh
java -jar github-webhook-listener <HOST> <PORT>
```