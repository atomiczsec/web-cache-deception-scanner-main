# Web Cache Deception Scanner - Burp Extension Community Edition

This is a Burp Suite extension to test web applications for various Web Cache Deception vulnerabilities. This version has been modified to work with the **Burp Suite Community Edition**.

## The scanner performs the following checks:

| Check | Description |
|-------|-------------|
| **Initial Path Mapping Check** | Verifies that the target endpoint responds differently to authenticated vs. unauthenticated requests, and checks if appending a random path segment (e.g., `/originalpath/randomXYZ`) returns content similar to the original path (`/originalpath`), confirming a prerequisite where the backend might ignore trailing path segments. |
| **Delimiter + Extension Cache Test** | If the initial check passes, iterates through common delimiters (`/`, `;`, `?`) and file extensions (e.g., `.js`, `.css`, `.jpg`, `.woff2`, `.pdf`). For each combination (e.g., `/originalpath/randomXYZ.js`), checks if requesting the URL without authentication returns content similar to the authenticated request, indicating the authenticated response was cached based on the extension. |
| **Path Normalization Cache Test** | Checks if the cache normalizes paths differently from the backend server using cacheable targets (e.g., `/robots.txt`, `/index.html`, `/assets/`). Iterates through delimiters and path traversal templates (e.g., `%2f%2e%2e%2f`), crafting URLs like `/originalpath;%2f%2e%2e%2frobots.txt` and comparing authenticated vs. unauthenticated responses to detect cache normalization vulnerabilities. |

## Installation (Community Edition)

### Option 1: Download Pre-built Release (Recommended)

1. Visit the [Releases page](https://github.com/atomiczsec/Web-Cache-Scanner/releases)
2. Download the latest `web-cache-deception-scanner-all.jar` from the **Latest build** release
3. In Burp Suite, go to the **Extender** tab
4. Click **Add** and select the downloaded JAR file
5. Check the **Output** tab for loading confirmation

### Option 2: Build from Source

**Prerequisites:**
- Java JDK 11 or higher
- Gradle (or use the included Gradle Wrapper)

**Build Steps:**

1. Clone the repository:
   ```bash
   git clone https://github.com/atomiczsec/Web-Cache-Scanner.git
   cd Web-Cache-Scanner
   ```

2. Build the extension using Gradle:
   ```bash
   ./gradlew clean build
   ```
   Or on Windows:
   ```bash
   gradlew.bat clean build
   ```

3. The built JAR file will be located at `build/libs/web-cache-deception-scanner-all.jar`

4. Install in Burp Suite:
   - Open Burp Suite and go to the **Extender** tab
   - Click **Add** and select the JAR file from `build/libs/`
   - Verify installation in the **Output** tab

## Credits

Original extension by [Johan Snyman](mailto:jsnyman@trustwave.com). Vulnerability research by [Omer Gil](https://twitter.com/omer_gil). Community Edition updates by [atomiczsec](https://atomiczsec.net).

---

<h3 align="center">Connect with me:</h3>

<p align="center">

  <a href="https://github.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/github.svg" height="30" width="40" /></a>

  <a href="https://instagram.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/instagram.svg" height="30" width="40" /></a>

  <a href="https://twitter.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" height="30" width="40" /></a>

  <a href="https://medium.com/@atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/medium.svg" height="30" width="40" /></a>

  <a href="https://youtube.com/@atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/youtube.svg" height="30" width="40" /></a>

</p>
