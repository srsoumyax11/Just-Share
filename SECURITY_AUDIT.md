# Security Audit Report - Bee File Sharing Application

**Audit Date:** 07 Feb 2026
**Application:** Bee - Local File Sharing  
**Version:** Latest (dev)  
**Auditor:** @Designerpro13

---

## 📊 Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
|   **Critical** | 5 |   Requires Immediate Action |
|   **High** | 7 |   Requires Action |
|   **Medium** | 6 |   Should Fix |
|  **Low** | 4 |  Consider Fixing |
| **Total Issues** | **22** | |

---

##   CRITICAL Severity Issues

### 1. Hardcoded Default PIN (111111)
**File:** `main.go:20`  
**Severity:**   Critical  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Description:**  
The application uses a hardcoded default PIN "111111" that is publicly documented in the README. This provides no real security as attackers can easily gain unauthorized access.

```go
if *pin == "" {
    *pin = "111111" // Hardcoded for now
}
```

**Impact:**  
- Anyone on the network can access the file sharing service
- No authentication barrier for malicious actors
- Files can be uploaded/downloaded without authorization

**Recommendation:**
- Generate a random 6-digit PIN on startup
- Display the PIN only in the terminal (not in README)
- Implement PIN change functionality
- Add rate limiting for PIN attempts

---

### 2. Path Traversal Vulnerability in File Upload
**File:** `internal/server/server.go:232-234`  
**Severity:**   Critical  
**CWE:** CWE-22 (Path Traversal)

**Description:**  
The file upload handler uses `filepath.Base()` but doesn't validate against malicious filenames. An attacker could potentially craft filenames with path traversal sequences.

```go
filename := filepath.Base(part.FileName())
savePath := filepath.Join("uploads", filename)
```

**Impact:**  
- Potential file overwrite outside uploads directory
- Directory traversal attacks
- Arbitrary file write on the server

**Recommendation:**
```go
// Sanitize filename
filename := filepath.Base(part.FileName())
filename = strings.ReplaceAll(filename, "..", "")
filename = strings.ReplaceAll(filename, "/", "")
filename = strings.ReplaceAll(filename, "\\", "")
if filename == "" || filename == "." {
    continue
}
```

---

### 3. No File Size Limits - Denial of Service
**File:** `internal/server/server.go:245`  
**Severity:**   Critical  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Description:**  
The application has no file size limits, allowing attackers to upload arbitrarily large files and exhaust disk space.

```go
size, err := io.Copy(dst, part) // No size limit
```

**Impact:**  
- Disk space exhaustion
- Server crash/unavailability
- Denial of service for legitimate users

**Recommendation:**
```go
// Add size limit (e.g., 10GB)
const maxFileSize = 10 * 1024 * 1024 * 1024
limitedReader := io.LimitReader(part, maxFileSize)
size, err := io.Copy(dst, limitedReader)
if size >= maxFileSize {
    dst.Close()
    os.Remove(savePath)
    http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
    return
}
```

---

### 4. CORS Allows All Origins
**File:** `internal/server/server.go:195, 273`  
**Severity:**   Critical  
**CWE:** CWE-942 (Overly Permissive CORS Policy)

**Description:**  
The application sets `Access-Control-Allow-Origin: *` allowing any website to make requests to the file sharing server.

```go
w.Header().Set("Access-Control-Allow-Origin", "*")
```

**Impact:**  
- Cross-Site Request Forgery (CSRF) attacks
- Malicious websites can upload/download files
- Data exfiltration from user's browser

**Recommendation:**
```go
// Only allow same-origin or specific trusted origins
origin := r.Header.Get("Origin")
if origin == "" || strings.HasPrefix(origin, "http://"+r.Host) {
    w.Header().Set("Access-Control-Allow-Origin", origin)
}
```

---

### 5. WebSocket Origin Validation Disabled
**File:** `internal/server/server.go:38-40`  
**Severity:**   Critical  
**CWE:** CWE-346 (Origin Validation Error)

**Description:**  
WebSocket upgrader accepts connections from any origin without validation.

```go
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // Allow all for LAN
    },
}
```

**Impact:**  
- Cross-Site WebSocket Hijacking (CSWSH)
- Malicious websites can establish WebSocket connections
- Unauthorized access to real-time user data

**Recommendation:**
```go
CheckOrigin: func(r *http.Request) bool {
    origin := r.Header.Get("Origin")
    return origin == "" || strings.HasPrefix(origin, "http://"+r.Host)
}
```

---

##   HIGH Severity Issues

### 6. No Rate Limiting on PIN Authentication
**File:** `internal/server/server.go:63-68`  
**Severity:**   High  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Description:**  
No rate limiting on WebSocket PIN authentication allows brute force attacks.

**Impact:**  
- Brute force attacks on 6-digit PIN (1 million combinations)
- Automated attacks can compromise access quickly

**Recommendation:**
- Implement rate limiting (e.g., 5 attempts per IP per minute)
- Add exponential backoff after failed attempts
- Log failed authentication attempts

---

### 7. Sensitive Information Logged
**File:** `internal/server/server.go:66`  
**Severity:**   High  
**CWE:** CWE-532 (Information Exposure Through Log Files)

**Description:**  
Failed authentication attempts log the attempted PIN in plaintext.

```go
log.Printf("AUTH FAILED: IP=%s Name=%s PIN=%s (Expected: %s)", ...)
```

**Impact:**  
- PIN exposure in log files
- Credentials visible to anyone with log access

**Recommendation:**
```go
log.Printf("AUTH FAILED: IP=%s Name=%s", r.RemoteAddr, name)
```

---

### 8. No HTTPS/TLS Support
**File:** `internal/server/server.go:177`  
**Severity:**   High  
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

**Description:**  
All communication happens over unencrypted HTTP, exposing data to network sniffing.

```go
http.ListenAndServe(":"+s.Port, nil)
```

**Impact:**  
- PIN transmitted in cleartext
- File contents visible to network attackers
- Man-in-the-middle attacks possible

**Recommendation:**
- Add optional TLS support with self-signed certificates
- Provide flag for HTTPS mode
- Warn users about unencrypted transmission

---

### 9. No Input Validation on User Name
**File:** `internal/server/server.go:69-72`  
**Severity:**   High  
**CWE:** CWE-20 (Improper Input Validation)

**Description:**  
User names are not validated for length or content, allowing injection attacks.

**Impact:**  
- XSS attacks through malicious usernames
- Log injection attacks
- UI breaking with extremely long names

**Recommendation:**
```go
if name == "" || len(name) > 50 {
    http.Error(w, "Invalid Name", http.StatusBadRequest)
    return
}
// Sanitize name
name = html.EscapeString(name)
```

---

### 10. Directory Listing Enabled
**File:** `internal/server/server.go:54`  
**Severity:**   High  
**CWE:** CWE-548 (Directory Listing)

**Description:**  
The uploads directory is served with directory listing enabled, allowing enumeration of all files.

```go
http.Handle("/upload/", http.StripPrefix("/upload/", http.FileServer(http.Dir("uploads"))))
```

**Impact:**  
- Attackers can enumerate all uploaded files
- Privacy violation for users
- Information disclosure

**Recommendation:**
- Disable directory listing
- Serve files only through authenticated endpoints
- Implement file access control

---

### 11. No File Type Validation
**File:** `internal/server/server.go:232-250`  
**Severity:**   High  
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)

**Description:**  
No validation of uploaded file types, allowing malicious executables.

**Impact:**  
- Malware distribution through the platform
- Executable files can be uploaded and shared
- Social engineering attacks

**Recommendation:**
```go
// Validate file extension
ext := strings.ToLower(filepath.Ext(filename))
dangerousExts := []string{".exe", ".bat", ".cmd", ".sh", ".ps1", ".scr"}
for _, dangerous := range dangerousExts {
    if ext == dangerous {
        http.Error(w, "File type not allowed", http.StatusBadRequest)
        return
    }
}
```

---

### 12. Weak Session Management
**File:** `frontend/src/App.jsx:44-48`  
**Severity:**   High  
**CWE:** CWE-522 (Insufficiently Protected Credentials)

**Description:**  
PIN is stored in localStorage without encryption, accessible to any JavaScript code.

```javascript
localStorage.setItem('js_name', name);
localStorage.setItem('js_pin', pin);
```

**Impact:**  
- XSS attacks can steal PIN
- Persistent storage of credentials
- No session expiration

**Recommendation:**
- Use sessionStorage instead of localStorage
- Implement session timeout
- Clear credentials on browser close

---

##   MEDIUM Severity Issues

### 13. No Content Security Policy (CSP)
**File:** Frontend serving (no CSP headers)  
**Severity:**   Medium  
**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers)

**Description:**  
No Content Security Policy headers to prevent XSS attacks.

**Recommendation:**
```go
w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
```

---

### 14. Missing Security Headers
**File:** `internal/server/server.go`  
**Severity:**   Medium  
**CWE:** CWE-693 (Protection Mechanism Failure)

**Description:**  
Missing security headers like X-Frame-Options, X-Content-Type-Options, etc.

**Recommendation:**
```go
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-XSS-Protection", "1; mode=block")
w.Header().Set("Referrer-Policy", "no-referrer")
```

---

### 15. Predictable File Naming on Collision
**File:** `internal/server/server.go:237-240`  
**Severity:**   Medium  
**CWE:** CWE-330 (Use of Insufficiently Random Values)

**Description:**  
File collision resolution uses Unix timestamp, which is predictable.

```go
filename = fmt.Sprintf("%d_%s", time.Now().Unix(), filename)
```

**Recommendation:**
```go
import "crypto/rand"
randomBytes := make([]byte, 8)
rand.Read(randomBytes)
filename = fmt.Sprintf("%x_%s", randomBytes, filename)
```

---

### 16. No Audit Logging
**File:** All files  
**Severity:**   Medium  
**CWE:** CWE-778 (Insufficient Logging)

**Description:**  
Insufficient logging of security events (file access, downloads, failed auth).

**Recommendation:**
- Log all file uploads with user info
- Log all file downloads
- Log authentication failures
- Implement structured logging

---

### 17. WebSocket Connection Leak
**File:** `internal/server/server.go:95-130`  
**Severity:**   Medium  
**CWE:** CWE-404 (Improper Resource Shutdown)

**Description:**  
Potential goroutine leak if WebSocket cleanup fails.

**Recommendation:**
- Add context with timeout
- Ensure all goroutines properly terminate
- Add connection pool limits

---

### 18. No File Deletion Capability
**File:** Missing feature  
**Severity:**   Medium  
**CWE:** CWE-459 (Incomplete Cleanup)

**Description:**  
No way to delete uploaded files, leading to indefinite storage.

**Recommendation:**
- Add authenticated file deletion endpoint
- Implement automatic cleanup of old files
- Add file retention policies

---

##  LOW Severity Issues

### 19. Verbose Error Messages
**File:** Multiple locations  
**Severity:**  Low  
**CWE:** CWE-209 (Information Exposure Through Error Message)

**Description:**  
Error messages may expose internal implementation details.

**Recommendation:**
- Use generic error messages for users
- Log detailed errors server-side only

---

### 20. No Graceful Shutdown for Uploads
**File:** `internal/server/server.go:172-175`  
**Severity:**  Low  
**CWE:** CWE-404 (Improper Resource Shutdown)

**Description:**  
Server shutdown doesn't wait for in-progress uploads to complete.

**Recommendation:**
- Implement graceful shutdown with timeout
- Track active uploads
- Wait for completion before exit

---

### 21. Browser Auto-Open Commented Out
**File:** `main.go:30, internal/server/server.go:165`  
**Severity:**  Low  
**CWE:** N/A (Usability)

**Description:**  
Browser auto-open is commented out, reducing user experience.

**Recommendation:**
- Add flag to enable/disable auto-open
- Make it configurable

---

### 22. No Version Check or Update Mechanism
**File:** `main.go:13`  
**Severity:**  Low  
**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

**Description:**  
No mechanism to check for security updates.

**Recommendation:**
- Implement version check on startup
- Notify users of available updates
- Add auto-update capability

---

## 🛠️ Remediation Priority

### Immediate (Week 1)
1.   Remove hardcoded PIN, generate random PIN
2.   Fix path traversal vulnerability
3.   Add file size limits
4.   Fix CORS policy
5.   Fix WebSocket origin validation

### Short-term (Week 2-4)
6.   Implement rate limiting
7.   Remove PIN from logs
8.   Add input validation
9.   Disable directory listing
10.   Add file type validation

### Medium-term (Month 2-3)
11.   Add TLS/HTTPS support
12.   Implement security headers
13.   Add audit logging
14.   Fix session management

### Long-term (Month 3+)
15.   Add file deletion capability
16.   Implement file retention policies
17.   Add update mechanism
18.   Security documentation

---

## 📋 Security Best Practices Recommendations

### Authentication & Authorization
- [ ] Implement token-based authentication instead of PIN-only
- [ ] Add multi-factor authentication option
- [ ] Implement role-based access control (RBAC)
- [ ] Add session timeout and idle timeout

### Network Security
- [ ] Add TLS/HTTPS support with Let's Encrypt
- [ ] Implement IP whitelisting option
- [ ] Add firewall configuration guide
- [ ] Support VPN-only mode

### Data Protection
- [ ] Add optional file encryption at rest
- [ ] Implement end-to-end encryption for transfers
- [ ] Add file integrity checking (checksums)
- [ ] Implement secure file deletion (overwrite)

### Monitoring & Logging
- [ ] Implement centralized logging
- [ ] Add security event monitoring
- [ ] Create alerting for suspicious activity
- [ ] Add metrics and dashboards

### Compliance
- [ ] Add GDPR compliance features (data deletion)
- [ ] Implement audit trail
- [ ] Add privacy policy and terms of service
- [ ] Create security documentation

---

## 🔍 Testing Recommendations

### Security Testing
- [ ] Perform penetration testing
- [ ] Run OWASP ZAP scan
- [ ] Conduct fuzzing tests
- [ ] Test for SQL injection (if database added)
- [ ] Test for XSS vulnerabilities

### Load Testing
- [ ] Test with multiple concurrent uploads
- [ ] Test with large files (>10GB)
- [ ] Test with many connected clients (>100)
- [ ] Test network interruption handling

### Integration Testing
- [ ] Test cross-platform compatibility
- [ ] Test with various file types
- [ ] Test WebSocket reconnection
- [ ] Test graceful degradation

---

## 📝 Audit Methodology

This security audit was performed using:
- Static code analysis
- Manual code review
- Security best practices comparison
- OWASP guidelines
- CWE/SANS Top 25 vulnerabilities

**Note:** This audit is based on static analysis.

---

**End of Security Audit Report**
