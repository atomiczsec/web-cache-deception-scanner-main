# CLAUDE.md — Web Cache Deception Scanner

A guide for AI assistants working in this repository.

## Project Overview

This is a **Burp Suite extension** (BApp) that automatically detects Web Cache Deception vulnerabilities. It integrates with Burp Suite's scanning pipeline, adds a right-click context menu, and reports findings as standard Burp `IScanIssue` entries.

Language: **Java 11+**. Build system: **Gradle**. No test framework — validation is done manually inside Burp Suite.

---

## Repository Structure

```
Web-Cache-Scanner/
├── src/main/java/burp/
│   ├── BurpExtender.java        # Extension entry point + orchestration (~750 lines)
│   ├── RequestSender.java       # Core testing engine + response analysis (~1579 lines)
│   ├── WebCacheIssue.java       # IScanIssue implementation for reporting (~120 lines)
│   └── PerformanceConfig.java   # Adaptive performance tuning system (~310 lines)
├── .github/workflows/
│   └── build.yml                # CI: builds JAR, versions, creates GitHub releases
├── build.gradle                 # Gradle build + fatJar configuration
├── settings.gradle
├── BappManifest.bmf             # Burp extension metadata (UUID, version, entry point)
├── BappDescription.html         # Marketplace description
├── README.md                    # Installation and usage guide
└── gradle/wrapper/              # Gradle wrapper (do not modify)
```

---

## Core Modules

### `BurpExtender.java`
The main extension class. Implements `IBurpExtender`, `IContextMenuFactory`, and `IExtensionStateListener`.

Key responsibilities:
- Registers the extension with Burp callbacks on `registerExtenderCallbacks()`
- Creates a thread pool sized by `PerformanceConfig`
- Adds a context menu item ("Web Cache Deception Test") for manual scans
- Runs scanning in `ScannerThread` (inner class) with a **prioritized test sequence**:
  1. **Prerequisite check** — confirms the endpoint requires auth and accepts path manipulation
  2. **High-priority tests** (run first; skip remaining tests if high-severity found):
     - Self-referential normalization
     - Reverse traversal
     - Hash-based traversal
  3. **Medium-priority tests** (skipped if high-severity already found):
     - Delimiter + extension caching
     - Header-based cache key manipulation
     - HTTP Parameter Pollution (HPP)
     - Case sensitivity attacks
     - Unicode normalization
  4. **Low-priority tests**:
     - Path normalization caching
     - Relative normalization
     - Prefix normalization
- Logging helpers: `logDebug`, `logInfo`, `logWarning`, `logError`, `logTiming` — all write to Burp's Output tab

### `RequestSender.java`
The vulnerability testing engine. All individual test methods live here.

Key capabilities:
- **Response caching**: Caffeine cache with configurable TTL to avoid redundant requests
- **Rate limiting**: Per-host token bucket limiting
- **Circuit breaker**: Per-host failure tracking; stops hammering broken hosts
- **Retry logic**: Up to 3 retries with exponential backoff
- **Response similarity**: Uses both Jaro-Winkler (threshold 0.75) and Levenshtein (threshold 300) to compare responses
- **Dynamic content filtering**: Strips timestamps, CSRF tokens, session IDs, and UUIDs before comparison

Test methods:
- `testDelimiterExtension()` — path delimiters (`;`, `/`, `?`, `%23`, `@`, `~`, `|`) + static extensions
- `testNormalizationCaching()` — path normalization exploits
- `testHashPathTraversal()` — hash fragment (`#`) traversal
- `testSelfReferentialNormalization()` — self-referential path segments
- `testReverseTraversal()` — reverse path traversal to cacheable resources
- `testHeaderBasedCacheKey()` — `X-Forwarded-Host` / `X-Original-URL` header injection
- `testHPPCacheKey()` — HTTP Parameter Pollution
- `testCaseSensitivityAttack()` — case variation in cache keys
- `testUnicodeNormalization()` — Unicode encoding tricks

### `WebCacheIssue.java`
Implements Burp's `IScanIssue` interface. Always reports severity **High**, confidence **Tentative**. Includes exploitation instructions, example `curl` commands, and HTML-formatted remediation guidance.

### `PerformanceConfig.java`
Detects system resources at startup and selects a performance profile:
- **HIGH**: RAM > 4 GB AND CPU cores > 4 → 4× thread multiplier
- **MEDIUM**: RAM > 2 GB AND CPU cores > 2 → 2× thread multiplier
- **LOW** (default): 1× thread multiplier

Override via system properties or environment variables:
```
WEBCACHE_PROFILE=HIGH
WEBCACHE_THREAD_MULTIPLIER=4
WEBCACHE_CACHE_SIZE=50000   # entries (range: 2000–50000)
WEBCACHE_RATE_LIMIT=100     # requests/second (range: 20–100)
WEBCACHE_CACHE_TTL=20       # minutes (range: 10–30)
```

---

## Build System

### Build commands

```bash
# Build the fat JAR (includes all dependencies)
./gradlew fatJar

# Clean + build
./gradlew clean build

# Windows
gradlew.bat fatJar
```

Output: `build/libs/web-cache-deception-scanner-all.jar`

### Dependencies (build.gradle)

| Artifact | Version | Purpose |
|---|---|---|
| `net.portswigger.burp.extender:burp-extender-api` | 2.3 | Burp Suite extension API |
| `org.apache.commons:commons-lang3` | 3.12.0 | String utilities |
| `org.apache.commons:commons-text` | 1.10.0 | Jaro-Winkler similarity |
| `com.github.ben-manes.caffeine:caffeine` | 3.1.8 | High-performance cache |

Java source/target compatibility: **11**.

The `fatJar` Gradle task bundles everything into a single self-contained JAR for loading into Burp.

---

## CI/CD Pipeline (`.github/workflows/build.yml`)

Triggers on:
- Push to `main` or `master`
- Pull request creation
- Manual workflow dispatch

Steps:
1. Checkout + set up JDK 11 (Temurin)
2. Build with `./gradlew fatJar`
3. Auto-increment minor version (e.g., `v2.0` → `v2.1`) on pushes to main
4. Create a GitHub Release with the JAR attached
5. Retain build artifacts for 30 days

When modifying the build pipeline, keep the `BuildCommand` in `BappManifest.bmf` in sync with `build.gradle`.

---

## Code Conventions

### General style
- Standard Java conventions (camelCase methods, PascalCase classes)
- Comprehensive null-checks before processing HTTP messages
- All shared mutable state uses `ConcurrentHashMap`, `AtomicInteger`, or `AtomicLong`
- Compiler warnings are enabled (`-Xlint:unchecked`, `-Xlint:deprecation`) — fix any new warnings introduced

### Logging
Use the logging helpers in `BurpExtender`, not `System.out`:
```java
logDebug(tag, message);
logInfo(tag, message);
logWarning(tag, message);
logError(tag, message);
logTiming(tag, elapsedMs);
```
All output appears in Burp Suite's Output tab with timestamps and severity level.

### Similarity comparison
When determining whether two responses are "equivalent" (i.e., the caching attack didn't change the response):
- Apply `filterDynamicContent()` first to strip volatile fields
- Use **both** Jaro-Winkler (≥ 0.75 = similar) **and** Levenshtein (≤ 300 = similar)
- A response is considered "different" (potential cache hit) only when **both** metrics indicate divergence

### Thread safety
- `BurpExtender` uses a `ThreadPoolExecutor` — never block the Burp EDT
- `RequestSender` rate limiters and circuit breakers are keyed per host using `ConcurrentHashMap`
- New shared state must use concurrent collections or explicit synchronization

### Adding new test vectors
1. Add the test method to `RequestSender.java` following the pattern of existing methods
2. Classify it HIGH / MEDIUM / LOW priority
3. Wire it into `ScannerThread.run()` in `BurpExtender.java` at the appropriate priority level
4. Update `WebCacheIssue.java` if the new vector requires distinct reporting language
5. Document the vector in `README.md`

---

## Testing

There is no automated test suite. To validate changes:
1. Build the fat JAR: `./gradlew fatJar`
2. Load into Burp Suite: Extender → Add → select the JAR
3. Right-click a request in Proxy history → "Web Cache Deception Test"
4. Inspect the Output tab for log output and the Issues tab for findings

Test against a local instance of a vulnerable application (e.g., a deliberately misconfigured Nginx + app stack) to avoid unintended testing of production systems.

---

## Extension Metadata

`BappManifest.bmf` must stay consistent with the build:

| Field | Value |
|---|---|
| UUID | `7c1ca94a61474d9e897d307c858d52f0` |
| Name | Web Cache Deception Scanner |
| EntryPoint | `build/libs/web-cache-deception-scanner-all.jar` |
| BuildCommand | `gradle fatJar` |

Do not change the UUID — it identifies the extension in the Burp BApp store.

---

## Security Considerations

- This tool sends **crafted HTTP requests** to target servers. Only run it against systems you are authorized to test.
- The extension does not exfiltrate data; it only reads response metadata to infer caching behavior.
- Rate limiting and circuit breakers are built in to avoid overwhelming targets.
- Never commit credentials, session tokens, or real target URLs into the repository.
