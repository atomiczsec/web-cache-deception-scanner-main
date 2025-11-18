# Web Cache Deception Scanner - Burp Extension Community Edition

This is a Burp Suite extension to test web applications for various Web Cache Deception vulnerabilities. This version has been modified to work with the **Burp Suite Community Edition**.

## The scanner performs the following checks:

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

## Installation (Community Edition)

{updating, work in progress}

## Credits

- **Original Extension Author:**  
  [Johan Snyman](mailto:jsnyman@trustwave.com)

- **Vulnerability Research:**  
  [Omer Gil](https://twitter.com/omer_gil) - *Pioneer of the Web Cache Deception attack*

- **Burp Community Edition Updates & Enhancements:**  
  [atomiczsec](https://atomiczsec.net) & cursor (AI assistant)
