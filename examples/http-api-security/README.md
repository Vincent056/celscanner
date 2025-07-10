# HTTP API Security Scanning Example

This example demonstrates how to use the CEL Go Scanner to perform comprehensive security scanning of REST API endpoints using HTTP fetchers.

## Features Demonstrated

### 🌐 HTTP Fetcher Capabilities
- GET, POST, PUT, DELETE, OPTIONS HTTP methods
- Custom headers and authentication
- Request timeouts and retry mechanisms
- JSON and text response parsing
- Response time measurement
- SSL/TLS verification

### 🔒 Security Checks
- **Authentication & Authorization**: Verify protected endpoints require proper auth
- **Security Headers**: Check for X-Frame-Options, X-Content-Type-Options, etc.
- **CORS Configuration**: Validate Cross-Origin Resource Sharing headers
- **SSL/TLS**: Ensure HTTPS usage and proper certificate validation
- **Rate Limiting**: Detect rate limiting headers and responses
- **Error Handling**: Verify graceful error responses

### ⚡ Performance & Reliability
- **Response Time**: Monitor API response times
- **Availability**: Check endpoint health and uptime
- **Error Rates**: Track 4xx/5xx response codes
- **Content Type**: Verify proper Content-Type headers

## Running the Example

```bash
# From the project root
make example-http-api-security

# Or run directly
cd examples/http-api-security
go run main.go
```

## Example Rules

### 1. Health Check Validation
```cel
health.success && health.statusCode == 200
```

### 2. Performance Monitoring
```cel
api.success && api.responseTime < 3000
```

### 3. Security Headers
```cel
headers.success &&
(has(headers.headers["X-Frame-Options"]) || has(headers.headers["x-frame-options"])) &&
(has(headers.headers["X-Content-Type-Options"]) || has(headers.headers["x-content-type-options"]))
```

### 4. Authentication Requirements
```cel
!basic_auth.success && basic_auth.statusCode == 401
```

### 5. POST Data Handling
```cel
post.success &&
post.statusCode == 200 &&
has(post.body.json) &&
post.body.json.test == "data"
```

## HTTP Response Structure

The HTTP fetcher provides the following response structure:

```json
{
  "statusCode": 200,
  "success": true,
  "headers": {
    "Content-Type": ["application/json"],
    "X-Frame-Options": ["DENY"]
  },
  "body": {
    "key": "parsed JSON or raw text"
  },
  "rawBody": "raw response body string",
  "responseTime": 150,
  "error": "",
  "metadata": {
    "url": "https://api.example.com/endpoint",
    "method": "GET"
  }
}
```

## Use Cases

### 🏢 Enterprise API Security
- Validate security policies across microservices
- Monitor API gateway configurations
- Check authentication and authorization
- Verify rate limiting and CORS policies

### 🔄 CI/CD Integration
- Automated security testing in pipelines
- Pre-deployment API validation
- Security regression testing
- Compliance verification

### 📊 API Monitoring
- Health check automation
- Performance monitoring
- SLA validation
- Error rate tracking

### 🛡️ Security Auditing
- Penetration testing support
- Vulnerability assessment
- Security header validation
- SSL/TLS configuration checks

## Advanced Configuration

### Custom Headers
```go
celscanner.NewRuleBuilder("api-auth-check").
    WithHTTPInput("api", "https://api.example.com/data", "GET", map[string]string{
        "Authorization": "Bearer " + token,
        "X-API-Version": "v2",
        "User-Agent": "Security-Scanner/1.0",
    }, nil).
    SetExpression(`api.success && api.statusCode == 200`).
    Build()
```

### POST with JSON Body
```go
payload := []byte(`{"query": "security scan", "filters": {"type": "endpoint"}}`)
celscanner.NewRuleBuilder("api-search").
    WithHTTPInput("search", "https://api.example.com/search", "POST", map[string]string{
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
    }, payload).
    SetExpression(`search.success && size(search.body.results) > 0`).
    Build()
```

### Timeout and Retry Configuration
```go
fetcher := fetchers.NewCompositeFetcherBuilder().
    WithHTTP(
        10*time.Second, // 10 second timeout
        false,          // don't follow redirects
        5,              // 5 retries
    ).
    Build()
```

## Real-World Examples

### Microservices Health Check
```cel
health.success && 
health.statusCode == 200 && 
has(health.body.status) && 
health.body.status == "healthy" &&
health.responseTime < 1000
```

### API Gateway Security
```cel
gateway.success &&
has(gateway.headers["X-Rate-Limit-Limit"]) &&
has(gateway.headers["X-Frame-Options"]) &&
has(gateway.headers["Content-Security-Policy"])
```

### OAuth Token Validation
```cel
oauth.statusCode == 401 &&
has(oauth.headers["WWW-Authenticate"]) &&
oauth.headers["WWW-Authenticate"][0].contains("Bearer")
```

## Compliance Frameworks

This example supports validation against:
- **OWASP API Security Top 10**
- **NIST Cybersecurity Framework**
- **CIS Controls**
- **ISO 27001**
- **SOC 2 Type II**

## Troubleshooting

### Common Issues

1. **Certificate Errors**: For self-signed certificates, configure HTTP client appropriately
2. **Timeout Issues**: Adjust timeout values for slow APIs
3. **Rate Limiting**: Implement delays between requests if needed
4. **CORS Preflight**: Use OPTIONS method for CORS validation

### Debug Mode
Enable debug logging to see detailed HTTP request/response information:

```go
config := celscanner.ScanConfig{
    EnableDebugLogging: true,
    // ... other config
}
```

## Performance Considerations

- **Concurrent Requests**: HTTP fetcher supports concurrent scanning
- **Connection Pooling**: Reuses HTTP connections for better performance
- **Request Caching**: Consider caching for repeated requests
- **Timeout Management**: Set appropriate timeouts for your environment

## Security Best Practices

1. **Secure Credentials**: Never hardcode API keys or tokens
2. **Environment Variables**: Use environment variables for sensitive data
3. **Network Security**: Scan from appropriate network segments
4. **Rate Limiting**: Respect API rate limits to avoid blocking
5. **Error Handling**: Properly handle and log security errors 