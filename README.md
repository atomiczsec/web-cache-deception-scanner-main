# Web Cache Deception Scanner - Burp Extension (Community Edition)

This is a Burp Suite extension to test web applications for various Web Cache Deception vulnerabilities. This version has been modified to work with the **Burp Suite Community Edition**.


## Disclaimer

This project was developed as an experiment with the assistance of artificial intelligence (AI). While every effort has been made to ensure accuracy and functionality, this extension is provided as-is and for research purposes only. The author(s) and contributors are not responsible for any use, misuse, or damages resulting from this software. Please use it responsibly and at your own risk.


## Functionality

Once the extension is loaded, testing can be initiated by right-clicking on a relevant request in the **Target -> Site map** or **Proxy -> HTTP History** tabs and selecting **"Web Cache Deception Test"** from the context menu.

The scanner performs the following checks:

1.  **Initial Path Mapping Check:**
    *   Verifies that the target endpoint responds differently to authenticated vs. unauthenticated requests (basic session check).
    *   Checks if appending a random path segment (e.g., `/originalpath/randomXYZ`) returns content similar to the original path (`/originalpath`). This confirms a prerequisite where the backend might ignore trailing path segments.

2.  **Delimiter + Extension Cache Test:**
    *   If the initial path mapping check passes, this test iterates through common delimiters (`/`, `;`, `?`) and a wide list of file extensions (e.g., `.js`, `.css`, `.jpg`, `.woff2`, `.pdf`).
    *   For each combination (e.g., `/originalpath/randomXYZ.js`, `/originalpath;randomXYZ.css`), it checks if requesting the URL *without* authentication returns content similar to requesting it *with* authentication.
    *   Similarity indicates that the authenticated response was likely cached based on the extension and served to the unauthenticated request.

3.  **Path Normalization Cache Test:**
    *   This test checks if the cache normalizes paths differently from the backend server, using common cacheable file/path targets (e.g., `/robots.txt`, `/index.html`, `/assets/`).
    *   It iterates through common delimiters (`/`, `;`, `?`) and several path traversal/normalization templates (e.g., `%2f%2e%2e%2f` which is `/../`).
    *   It crafts URLs combining the original path, a delimiter, a normalization template, and a known cacheable target (e.g., `/originalpath;%2f%2e%2e%2frobots.txt`).
    *   Similar to the previous test, it compares the response body received by an authenticated vs. unauthenticated request for this crafted URL.
    *   Similarity suggests the cache might have normalized the path (e.g., to `/robots.txt`) and cached the sensitive content from `/originalpath` under that key.

## Building the Extension (Community Edition)

This version uses Gradle. Ensure you have a JDK (e.g., OpenJDK 11 or later) and Gradle installed and configured.

1.  Clone the repository.
2.  Navigate to the project directory in your terminal.
3.  Generate the Gradle wrapper (if missing): `gradle wrapper`
4.  Build the extension JAR: `./gradlew clean build`
5.  The required JAR file (`web-cache-deception-scanner-all.jar`) will be located in the `build/libs/` directory.

## Installation (Community Edition)

1.  Build the extension JAR as described above.
2.  In Burp Suite Community, go to the **Extender** tab.
3.  Under the **Extensions** sub-tab, click the **Add** button.
4.  Set **Extension type** to **Java**.
5.  Click **Select file...** and choose the `web-cache-deception-scanner-all.jar` file from the `build/libs` directory.
6.  Click **Next**.
7.  Check the **Output** tab for the loading messages and credits:
    ```
    Web Cache Deception Scanner Version 1.2
    Original Author: Johan Snyman <jsnyman@trustwave.com>
    Updated for Burp Community by: atomiczsec <https://atomiczsec.net>
    ```

## Credits

- **Original Extension Author:**  
  [Johan Snyman](mailto:jsnyman@trustwave.com)

- **Vulnerability Research:**  
  [Omer Gil](https://twitter.com/omer_gil) - *Pioneer of the Web Cache Deception attack*

- **Burp Community Edition Updates & Enhancements:**  
  [atomiczsec](https://atomiczsec.net) & cursor (AI assistant)
