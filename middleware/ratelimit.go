package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter 限流器接口
type RateLimiter interface {
	Allow(key string) (bool, time.Duration)
}

// TokenBucketRateLimiter 基于令牌桶的限流器
type TokenBucketRateLimiter struct {
	mu       sync.RWMutex
	buckets  map[string]*Bucket
	rate     int           // 每秒令牌数
	capacity int           // 桶容量
}

type Bucket struct {
	tokens    float64
	lastRefill time.Time
}

// NewTokenBucketRateLimiter 创建新的令牌桶限流器
func NewTokenBucketRateLimiter(rate, capacity int) *TokenBucketRateLimiter {
	rl := &TokenBucketRateLimiter{
		buckets:  make(map[string]*Bucket),
		rate:     rate,
		capacity: capacity,
	}
	
	// 启动清理goroutine
	go rl.cleanup()
	
	return rl
}

// Allow 检查是否允许请求
func (rl *TokenBucketRateLimiter) Allow(key string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &Bucket{
			tokens:    float64(rl.capacity),
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
	}
	
	// 计算需要添加的令牌数
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refill := float64(elapsed.Seconds()) * float64(rl.rate)
	
	bucket.tokens += refill
	if bucket.tokens > float64(rl.capacity) {
		bucket.tokens = float64(rl.capacity)
	}
	bucket.lastRefill = now
	
	// 检查是否有足够的令牌
	if bucket.tokens >= 1 {
		bucket.tokens -= 1
		return true, 0
	}
	
	// 计算需要等待的时间
	waitTime := time.Duration((1 - bucket.tokens) / float64(rl.rate) * float64(time.Second))
	return false, waitTime
}

// cleanup 清理过期的桶
func (rl *TokenBucketRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, bucket := range rl.buckets {
				// 如果桶为空且5分钟没有活动，则删除
				if bucket.tokens == 0 && now.Sub(bucket.lastRefill) > 5*time.Minute {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// RateLimit 限流中间件
func RateLimit(limiter RateLimiter, limitKeyFunc func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := limitKeyFunc(c)
		if key == "" {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Rate limit key is empty",
			})
			return
		}
		
		allowed, waitTime := limiter.Allow(key)
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(int(waitTime.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"retryAfter": waitTime.String(),
			})
			return
		}
		
		c.Header("X-RateLimit-Limit", "100")
		c.Header("X-RateLimit-Remaining", "99")
		c.Header("X-RateLimit-Reset", time.Now().Add(time.Second).Format(time.RFC3339))
		
		c.Next()
	}
}

// IPRateLimit IP限流中间件
func IPRateLimit(limiter RateLimiter, maxRequests int) gin.HandlerFunc {
	return RateLimit(limiter, func(c *gin.Context) string {
		return c.ClientIP() + ":" + c.Request.URL.Path
	})
}

// APILimit API限流中间件
func APILimit(limiter RateLimiter, apiKey string) gin.HandlerFunc {
	return RateLimit(limiter, func(c *gin.Context) string {
		return apiKey + ":" + c.Request.URL.Path
	})
}

// PerUserRateLimit 每用户限流中间件
func PerUserRateLimit(limiter RateLimiter) gin.HandlerFunc {
	return RateLimit(limiter, func(c *gin.Context) string {
		userID := c.GetString("user_id")
		if userID == "" {
			return c.ClientIP()
		}
		return "user:" + userID + ":" + c.Request.URL.Path
	})
}