# HTB-Writeup-CommandInjections
HackTheBox Writeup: Advanced Command Injections using Burp Suite, Intruder, curl, netcat, $IFS/$PATH manipulation, payload obfuscation, base64 encoding, and filter evasion techniques.

By Ramyar Daneshgar


## **Phase 1: Reconnaissance & Initial Analysis**
### **Target System Enumeration**
- **Environment:** Web-based file manager
- **Target IP:** *(Hidden)*
- **Authentication:** `guest:guest`
- **Primary Functionality Tested:** File operations (`Copy`, `Move`)
- **Hypothesis:** The backend may execute **system commands** (`mv`, `cp`, `ls`, `cat`).

At this stage, I manually explored the application’s functionality and identified **user-controllable input fields** that might be used to execute system commands. Since many file managers use **shell commands** under the hood, I focused on injection points within file handling operations.

---

## **Phase 2: Detecting Command Injection**
### **Step 1: Testing Injection Operators**
Using **Burp Suite**, I intercepted requests and injected **common command injection operators** (`;`, `&`, `|`, `&&`, `||`). This resulted in the following error:
```plaintext
Please match the requested format.
```
This indicated the presence of **front-end input validation**, possibly using **regex patterns** to restrict input.

### **Step 2: Reviewing Source Code for Validation**
By viewing the page source (`CTRL + U`), I identified a **client-side regex validation** on **line 17**:
```regex
pattern="^(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,2})$"
```
This pattern enforces **an IPv4 address format** but does not sanitize input at the server level. **Client-side validation alone is ineffective**, as it can be bypassed using **Burp Suite** or modifying the request in the browser's developer console.

---

## **Phase 3: Injecting Commands**
### **Step 1: Identifying Allowed Injection Operators**
I tested different operators in Burp Suite:
- `;` → **Blocked**
- `&` → **Allowed**
- `|` → **Only the second command output displayed**
- `%0a` (New-line) → **Allowed**

💡 **Key Finding:** The **new-line character (`%0a`)** was **not blacklisted**, allowing me to append commands to existing ones.

### **Step 2: Testing for Command Execution**
I injected the following payload to verify command execution:
```bash
127.0.0.1%0awhoami
```
**Result:** The application returned the currently logged-in user, confirming successful **command injection**.

---

## **Phase 4: Bypassing Space Filters**
### **Step 1: Executing `ls -la`**
Since **spaces were blacklisted**, I needed an alternative way to separate command arguments. I attempted:
```bash
ls$IFS-la
```
(`$IFS` is the **Internal Field Separator** in Linux, which defaults to a space.)

**Result:** Successfully listed directory contents, confirming that `$IFS` could replace spaces. This revealed `index.php`, which had a size of **1613 bytes**.

### **Why This Works**
- `$IFS` is a built-in shell variable used to separate arguments in command execution.
- Many applications only **blacklist direct spaces**, but **do not block `$IFS`**.
- Using `$IFS` allows executing multi-word commands **without spaces**.

---

## **Phase 5: Bypassing Other Blacklisted Characters**
### **Step 1: Locating Users in `/home`**
Since `/` (forward slash) was **blacklisted**, I extracted it dynamically from `$PATH`:
```bash
ls${PATH:0:1}home
```
(``${PATH:0:1}` extracts `/` from the system’s `$PATH` variable.)

**Result:** I found a user directory named **`1nj3c70r`**.

---

## **Phase 6: Bypassing Blacklisted Commands**
### **Step 1: Retrieving `flag.txt`**
Since `cat` was **blacklisted**, I attempted obfuscation:
```bash
c'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```
By **splitting characters with single quotes**, I evaded detection.

**Result:** The flag was successfully retrieved:
```plaintext
HTB{b451c_f1l73r5_w0n7_570p_m3}
```

---

## **Lessons Learned**
1. **Server-Side Validation is Critical**
   - Client-side validation is **easily bypassed** and should never be the sole security measure.
   - All input must be **validated server-side** using **whitelists instead of blacklists**.

2. **Filter Evasion Techniques Work**
   - Many applications rely on **blacklists**, which are **easily bypassed** using encoding, obfuscation, and alternative shell syntax.
   - Techniques like **Base64 encoding, variable expansion, and command splitting** effectively circumvent these restrictions.

3. **Error Handling Can Leak Information**
   - The **Move function** revealed error messages that helped me understand how commands were executed.
   - Applications should **sanitize error messages** to prevent **leakage of sensitive information**.

4. **Command Execution Should Be Avoided**
   - Directly executing **system commands** in web applications is inherently **risky**.
   - If necessary, commands should be **sandboxed, restricted, or executed with least privilege**.

5. **Web Application Firewalls (WAFs) are Not Foolproof**
   - While WAFs can block basic attacks, **advanced obfuscation techniques can still bypass them**.
   - Security should be **layered**, combining **WAFs, proper input handling, and least privilege principles**.

---

## **Mitigation Recommendations**
### **1. Remove System Command Execution**
- Use **built-in functions** instead of `system()`, `exec()`, or `shell_exec()`.
- Example: Use `fsockopen()` instead of `system("ping")`.

### **2. Enforce Strong Input Validation**
- Use **server-side validation** to check for expected values.
- Example:
  ```php
  if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) { ... }
  ```

### **3. Sanitize User Input**
- Remove all unnecessary characters:
  ```php
  $ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
  ```

### **4. Restrict Execution of Dangerous Functions**
- Disable **risky PHP functions**:
  ```ini
  disable_functions = system, exec, shell_exec, passthru
  ```

### **5. Harden Server Configuration**
- Use **WAFs** (e.g., Cloudflare, ModSecurity).
- Restrict application access using **least privilege** (`www-data` user).
- Implement **open_basedir** restrictions:
  ```ini
  open_basedir = "/var/www/html"
  ```

### **6. Perform Continuous Security Testing**
- Conduct **regular penetration tests** to identify vulnerabilities.
- Implement **security monitoring and logging** to detect exploitation attempts.

---

# **Conclusion**
This assessment successfully demonstrated **command injection**, **filter bypassing**, and **advanced obfuscation** techniques, proving the application was vulnerable. By **combining secure coding practices, server hardening, and continuous security assessments**, organizations can effectively mitigate such risks.

