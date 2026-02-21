package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	taskServiceURL := os.Getenv("TASK_SERVICE_URL")
	if taskServiceURL == "" {
		taskServiceURL = "http://localhost:8081"
	}

	crmServiceURL := os.Getenv("CRM_SERVICE_URL")
	if crmServiceURL == "" {
		crmServiceURL = "http://localhost:8082"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "secret"
		log.Println("WARNING: Using default JWT secret")
	}

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "gateway"})
	})

	r.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-User-ID, X-User-Role")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	authMiddleware := func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if userID, ok := claims["user_id"].(float64); ok {
				c.Request.Header.Set("X-User-ID", fmt.Sprintf("%.0f", userID))
			}
			if role, ok := claims["role"].(string); ok {
				c.Request.Header.Set("X-User-Role", role)
			}
		}

		c.Next()
	}

	proxy := func(target string) gin.HandlerFunc {
		url, err := url.Parse(target)
		if err != nil {
			log.Fatalf("Invalid target URL: %v", err)
		}
		proxy := httputil.NewSingleHostReverseProxy(url)

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = url.Host
		}

		proxy.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Del("Access-Control-Allow-Origin")
			resp.Header.Del("Access-Control-Allow-Credentials")
			resp.Header.Del("Access-Control-Allow-Headers")
			resp.Header.Del("Access-Control-Allow-Methods")
			return nil
		}

		return func(c *gin.Context) {
			proxy.ServeHTTP(c.Writer, c.Request)
		}
	}

	// Public routes (Login/Signup/Me/Teams)
	r.Any("/api/auth/*any", proxy(taskServiceURL))

	taskGroup := r.Group("/api/tasks")
	taskGroup.Use(authMiddleware)
	taskGroup.Any("", proxy(taskServiceURL))
	taskGroup.Any("/*any", proxy(taskServiceURL))

	deadlineGroup := r.Group("/api/deadline-requests")
	deadlineGroup.Use(authMiddleware)
	deadlineGroup.Any("", proxy(taskServiceURL))
	deadlineGroup.Any("/*any", proxy(taskServiceURL))

	teamGroup := r.Group("/api/teams")
	teamGroup.Use(authMiddleware)
	teamGroup.Any("", proxy(taskServiceURL))
	teamGroup.Any("/*any", proxy(taskServiceURL))

	userGroup := r.Group("/api/users")
	userGroup.Use(authMiddleware)
	userGroup.Any("", proxy(taskServiceURL))
	userGroup.Any("/*any", proxy(taskServiceURL))

	adminGroup := r.Group("/api/admin")
	adminGroup.Use(authMiddleware)
	adminGroup.Any("/*any", proxy(taskServiceURL))

	crmGroup := r.Group("/api/followups")
	crmGroup.Use(authMiddleware)
	crmGroup.Any("", proxy(crmServiceURL))
	crmGroup.Any("/*any", proxy(crmServiceURL))

	meetingGroup := r.Group("/api/meetings")
	meetingGroup.Use(authMiddleware)
	meetingGroup.Any("", proxy(crmServiceURL))
	meetingGroup.Any("/*any", proxy(crmServiceURL))

	reminderGroup := r.Group("/api/reminders")
	reminderGroup.Use(authMiddleware)
	reminderGroup.Any("", proxy(crmServiceURL))
	reminderGroup.Any("/*any", proxy(crmServiceURL))

	toolGroup := r.Group("/api/tool")
	toolGroup.Use(authMiddleware)
	toolGroup.Any("", proxy(crmServiceURL))
	toolGroup.Any("/*any", proxy(crmServiceURL))

	log.Printf("Gateway starting on port %s", port)
	r.Run(":" + port)
}
