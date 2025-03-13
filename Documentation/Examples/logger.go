// Basic usage with defaults
// router.Use(DefaultLoggingMiddleware())

// Customized configuration
// config := &LoggerConfig{
//     Level:        INFO,
//     Async:        true,
//     BufferSize:   2000,
//     Format:       "json",
//     ExcludePaths: []string{"/health", "/metrics", "/ping"},
// }
// router.Use(LoggingMiddleware(config))