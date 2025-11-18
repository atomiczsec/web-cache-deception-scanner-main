package burp;

/**
 * Performance configuration system for Web Cache Deception Scanner.
 * Supports auto-detection based on system resources and user overrides via
 * system properties or environment variables.
 */
public class PerformanceConfig {
    
    public enum Profile {
        LOW, MEDIUM, HIGH, CUSTOM
    }
    
    // Profile configurations
    private static final int LOW_THREAD_MULTIPLIER = 1;
    private static final int MEDIUM_THREAD_MULTIPLIER = 2;
    private static final int HIGH_THREAD_MULTIPLIER = 4;
    
    private static final int LOW_CACHE_SIZE = 2000;
    private static final int MEDIUM_CACHE_SIZE = 10000;
    private static final int HIGH_CACHE_SIZE = 50000;
    
    private static final int LOW_CACHE_TTL_MINUTES = 10;
    private static final int MEDIUM_CACHE_TTL_MINUTES = 15;
    private static final int HIGH_CACHE_TTL_MINUTES = 30;
    
    private static final int LOW_RATE_LIMIT = 20;
    private static final int MEDIUM_RATE_LIMIT = 50;
    private static final int HIGH_RATE_LIMIT = 100;
    
    private static final int LOW_DELAY_MS = 50;
    private static final int MEDIUM_DELAY_MS = 25;
    private static final int HIGH_DELAY_MS = 10;
    
    private static Profile currentProfile;
    private static int customThreadMultiplier = -1;
    private static int customCacheSize = -1;
    private static int customCacheTTLMinutes = -1;
    private static int customRateLimit = -1;
    private static int customDelayMs = -1;
    
    static {
        initialize();
    }
    
    /**
     * Initialize configuration by detecting system resources and applying user overrides.
     */
    private static void initialize() {
        // Check for user override first
        String profileOverride = getProfileOverride();
        if (profileOverride != null) {
            try {
                currentProfile = Profile.valueOf(profileOverride.toUpperCase());
                if (currentProfile == Profile.CUSTOM) {
                    loadCustomSettings();
                }
            } catch (IllegalArgumentException e) {
                // Invalid profile, fall back to auto-detection
                currentProfile = detectProfile();
            }
        } else {
            currentProfile = detectProfile();
        }
    }
    
    /**
     * Get profile override from system property or environment variable.
     */
    private static String getProfileOverride() {
        // Check system property first
        String prop = System.getProperty("webcache.profile");
        if (prop != null && !prop.isEmpty()) {
            return prop;
        }
        // Check environment variable
        String env = System.getenv("WEBCACHE_PROFILE");
        if (env != null && !env.isEmpty()) {
            return env;
        }
        return null;
    }
    
    /**
     * Load custom settings from system properties or environment variables.
     */
    private static void loadCustomSettings() {
        // Thread multiplier
        String threadMult = System.getProperty("webcache.thread.multiplier");
        if (threadMult == null) threadMult = System.getenv("WEBCACHE_THREAD_MULTIPLIER");
        if (threadMult != null) {
            try {
                customThreadMultiplier = Integer.parseInt(threadMult);
            } catch (NumberFormatException e) {
                // Invalid value, use default
            }
        }
        
        // Cache size
        String cacheSize = System.getProperty("webcache.cache.size");
        if (cacheSize == null) cacheSize = System.getenv("WEBCACHE_CACHE_SIZE");
        if (cacheSize != null) {
            try {
                customCacheSize = Integer.parseInt(cacheSize);
            } catch (NumberFormatException e) {
                // Invalid value, use default
            }
        }
        
        // Cache TTL
        String cacheTTL = System.getProperty("webcache.cache.ttl");
        if (cacheTTL == null) cacheTTL = System.getenv("WEBCACHE_CACHE_TTL");
        if (cacheTTL != null) {
            try {
                customCacheTTLMinutes = Integer.parseInt(cacheTTL);
            } catch (NumberFormatException e) {
                // Invalid value, use default
            }
        }
        
        // Rate limit
        String rateLimit = System.getProperty("webcache.rate.limit");
        if (rateLimit == null) rateLimit = System.getenv("WEBCACHE_RATE_LIMIT");
        if (rateLimit != null) {
            try {
                customRateLimit = Integer.parseInt(rateLimit);
            } catch (NumberFormatException e) {
                // Invalid value, use default
            }
        }
        
        // Delay
        String delay = System.getProperty("webcache.delay.ms");
        if (delay == null) delay = System.getenv("WEBCACHE_DELAY_MS");
        if (delay != null) {
            try {
                customDelayMs = Integer.parseInt(delay);
            } catch (NumberFormatException e) {
                // Invalid value, use default
            }
        }
    }
    
    /**
     * Auto-detect appropriate profile based on system resources.
     */
    private static Profile detectProfile() {
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        int availableProcessors = runtime.availableProcessors();
        
        // Convert bytes to GB
        long maxMemoryGB = maxMemory / (1024L * 1024L * 1024L);
        
        // Detection logic:
        // HIGH: RAM > 4GB AND cores > 4
        // MEDIUM: RAM > 2GB AND cores > 2
        // LOW: otherwise
        if (maxMemoryGB > 4 && availableProcessors > 4) {
            return Profile.HIGH;
        } else if (maxMemoryGB > 2 && availableProcessors > 2) {
            return Profile.MEDIUM;
        } else {
            return Profile.LOW;
        }
    }
    
    /**
     * Get the current performance profile.
     */
    public static Profile getProfile() {
        return currentProfile;
    }
    
    /**
     * Get thread pool multiplier based on current profile.
     */
    public static int getThreadMultiplier() {
        if (currentProfile == Profile.CUSTOM && customThreadMultiplier > 0) {
            return customThreadMultiplier;
        }
        switch (currentProfile) {
            case LOW:
                return LOW_THREAD_MULTIPLIER;
            case MEDIUM:
                return MEDIUM_THREAD_MULTIPLIER;
            case HIGH:
                return HIGH_THREAD_MULTIPLIER;
            default:
                return MEDIUM_THREAD_MULTIPLIER;
        }
    }
    
    /**
     * Get cache maximum size based on current profile.
     */
    public static int getCacheMaxSize() {
        if (currentProfile == Profile.CUSTOM && customCacheSize > 0) {
            return customCacheSize;
        }
        switch (currentProfile) {
            case LOW:
                return LOW_CACHE_SIZE;
            case MEDIUM:
                return MEDIUM_CACHE_SIZE;
            case HIGH:
                return HIGH_CACHE_SIZE;
            default:
                return MEDIUM_CACHE_SIZE;
        }
    }
    
    /**
     * Get cache TTL in seconds based on current profile.
     */
    public static int getCacheTTLSeconds() {
        int minutes;
        if (currentProfile == Profile.CUSTOM && customCacheTTLMinutes > 0) {
            minutes = customCacheTTLMinutes;
        } else {
            switch (currentProfile) {
                case LOW:
                    minutes = LOW_CACHE_TTL_MINUTES;
                    break;
                case MEDIUM:
                    minutes = MEDIUM_CACHE_TTL_MINUTES;
                    break;
                case HIGH:
                    minutes = HIGH_CACHE_TTL_MINUTES;
                    break;
                default:
                    minutes = MEDIUM_CACHE_TTL_MINUTES;
            }
        }
        return minutes * 60; // Convert to seconds
    }
    
    /**
     * Get rate limit (requests per second) based on current profile.
     */
    public static int getRateLimit() {
        if (currentProfile == Profile.CUSTOM && customRateLimit > 0) {
            return customRateLimit;
        }
        switch (currentProfile) {
            case LOW:
                return LOW_RATE_LIMIT;
            case MEDIUM:
                return MEDIUM_RATE_LIMIT;
            case HIGH:
                return HIGH_RATE_LIMIT;
            default:
                return MEDIUM_RATE_LIMIT;
        }
    }
    
    /**
     * Get delay in milliseconds for Thread.sleep() calls based on current profile.
     */
    public static int getDelayMs() {
        if (currentProfile == Profile.CUSTOM && customDelayMs > 0) {
            return customDelayMs;
        }
        switch (currentProfile) {
            case LOW:
                return LOW_DELAY_MS;
            case MEDIUM:
                return MEDIUM_DELAY_MS;
            case HIGH:
                return HIGH_DELAY_MS;
            default:
                return MEDIUM_DELAY_MS;
        }
    }
    
    /**
     * Get system resource information for logging.
     */
    public static String getSystemInfo() {
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        int availableProcessors = runtime.availableProcessors();
        
        long maxMemoryMB = maxMemory / (1024L * 1024L);
        long totalMemoryMB = totalMemory / (1024L * 1024L);
        long freeMemoryMB = freeMemory / (1024L * 1024L);
        
        return String.format(
            "System Resources - Max Memory: %d MB, Total Memory: %d MB, Free Memory: %d MB, CPU Cores: %d",
            maxMemoryMB, totalMemoryMB, freeMemoryMB, availableProcessors
        );
    }
    
    /**
     * Get configuration summary for logging.
     */
    public static String getConfigSummary() {
        return String.format(
            "Performance Profile: %s | Thread Multiplier: %dx | Cache Size: %d | Cache TTL: %d min | Rate Limit: %d req/sec | Delay: %d ms",
            currentProfile,
            getThreadMultiplier(),
            getCacheMaxSize(),
            getCacheTTLSeconds() / 60,
            getRateLimit(),
            getDelayMs()
        );
    }
}

