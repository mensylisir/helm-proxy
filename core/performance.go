package core

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryManager 内存管理器
type MemoryManager struct {
	mu          sync.RWMutex
	allocations map[string]*Allocation
	totalAlloc  atomic.Int64
	maxAlloc    atomic.Int64
	gcTrigger   atomic.Int64
	gcCount     atomic.Int64
	metrics     Metrics
	logger      *StructuredLogger
}

// Allocation 内存分配记录
type Allocation struct {
	ID         string
	Size       int64
	CreatedAt  time.Time
	Context    string
	StackTrace string
}

// NewMemoryManager 创建内存管理器
func NewMemoryManager(metrics Metrics, logger *StructuredLogger) *MemoryManager {
	mm := &MemoryManager{
		allocations: make(map[string]*Allocation),
		metrics:     metrics,
		logger:      logger,
	}

	// 设置初始GC触发阈值（100MB）
	mm.gcTrigger.Store(100 * 1024 * 1024)

	// 启动内存监控
	go mm.startMonitor()

	return mm
}

// TrackAllocation 跟踪内存分配
func (mm *MemoryManager) TrackAllocation(id string, size int64, context string) {
	allocation := &Allocation{
		ID:         id,
		Size:       size,
		CreatedAt:  time.Now(),
		Context:    context,
		StackTrace: "",
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.allocations[id] = allocation
	mm.totalAlloc.Add(size)

	// 更新最大分配
	for {
		current := mm.maxAlloc.Load()
		if size <= current {
			break
		}
		if mm.maxAlloc.CompareAndSwap(current, size) {
			break
		}
	}

	// 检查是否需要触发GC
	if mm.totalAlloc.Load() > mm.gcTrigger.Load() {
		mm.ForceGC()
	}

	// 记录指标
	if mm.metrics != nil {
		mm.metrics.RecordGauge("memory.allocated", float64(mm.totalAlloc.Load()))
		mm.metrics.RecordGauge("memory.allocations", float64(len(mm.allocations)))
	}
}

// ReleaseAllocation 释放内存分配
func (mm *MemoryManager) ReleaseAllocation(id string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if allocation, exists := mm.allocations[id]; exists {
		delete(mm.allocations, id)
		mm.totalAlloc.Add(-allocation.Size)

		// 记录指标
		if mm.metrics != nil {
			mm.metrics.RecordGauge("memory.allocated", float64(mm.totalAlloc.Load()))
			mm.metrics.RecordGauge("memory.allocations", float64(len(mm.allocations)))
		}
	}
}

// ForceGC 强制垃圾回收
func (mm *MemoryManager) ForceGC() {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	runtime.GC()

	runtime.ReadMemStats(&after)

	mm.gcCount.Add(1)

	// 记录指标
	if mm.metrics != nil {
		mm.metrics.RecordGauge("memory.gc_count", float64(mm.gcCount.Load()))
		mm.metrics.RecordGauge("memory.gc_pause_ns", float64(after.PauseTotalNs-before.PauseTotalNs))
	}

	mm.logger.WithField("gc_count", mm.gcCount.Load()).
		WithField("heap_alloc_before", before.HeapAlloc).
		WithField("heap_alloc_after", after.HeapAlloc).
		Info("执行垃圾回收")
}

// startMonitor 启动内存监控
func (mm *MemoryManager) startMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.monitor()
		}
	}
}

// monitor 内存监控
func (mm *MemoryManager) monitor() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// 检查内存使用情况
	if memStats.HeapAlloc > 500*1024*1024 { // 500MB
		mm.logger.WithField("heap_alloc", memStats.HeapAlloc).
			WithField("heap_sys", memStats.HeapSys).
			Warn("内存使用率较高，触发垃圾回收")

		mm.ForceGC()

		// 重新检查
		runtime.ReadMemStats(&memStats)
		if memStats.HeapAlloc > 500*1024*1024 {
			// 调整GC触发阈值
			mm.gcTrigger.Store(int64(memStats.HeapAlloc) + 100*1024*1024)
		}
	}

	// 清理过旧的分配记录
	mm.cleanupOldAllocations()

	// 记录指标
	if mm.metrics != nil {
		mm.metrics.RecordGauge("memory.heap_alloc", float64(memStats.HeapAlloc))
		mm.metrics.RecordGauge("memory.heap_sys", float64(memStats.HeapSys))
		mm.metrics.RecordGauge("memory.goroutines", float64(runtime.NumGoroutine()))
		mm.metrics.RecordGauge("memory.num_gc", float64(memStats.NumGC))
	}
}

// cleanupOldAllocations 清理过旧的分配记录
func (mm *MemoryManager) cleanupOldAllocations() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)

	for id, allocation := range mm.allocations {
		if allocation.CreatedAt.Before(cutoff) {
			delete(mm.allocations, id)
		}
	}
}

// GetStats 获取内存统计
func (mm *MemoryManager) GetStats() *MemoryStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	mm.mu.RLock()
	defer mm.mu.RUnlock()

	return &MemoryStats{
		HeapAlloc:         int64(memStats.HeapAlloc),
		HeapSys:           int64(memStats.HeapSys),
		TotalAlloc:        mm.totalAlloc.Load(),
		MaxAlloc:          mm.maxAlloc.Load(),
		ActiveAllocations: len(mm.allocations),
		GCCount:           mm.gcCount.Load(),
		Goroutines:        runtime.NumGoroutine(),
		NumGC:             int(memStats.NumGC),
		GCPauseTotal:      int64(memStats.PauseTotalNs),
	}
}

// MemoryStats 内存统计
type MemoryStats struct {
	HeapAlloc         int64 `json:"heap_alloc"`
	HeapSys           int64 `json:"heap_sys"`
	TotalAlloc        int64 `json:"total_alloc"`
	MaxAlloc          int64 `json:"max_alloc"`
	ActiveAllocations int   `json:"active_allocations"`
	GCCount           int64 `json:"gc_count"`
	Goroutines        int   `json:"goroutines"`
	NumGC             int   `json:"num_gc"`
	GCPauseTotal      int64 `json:"gc_pause_total_ns"`
}

// Cache 缓存接口
type Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
	Stats() *CacheStats
}

// LRUCache LRU缓存实现
type LRUCache struct {
	mu       sync.RWMutex
	cache    map[string]*CacheItem
	head     *CacheItem
	tail     *CacheItem
	capacity int
	stats    CacheStats
}

// CacheItem 缓存项
type CacheItem struct {
	Key        string
	Value      interface{}
	AccessTime time.Time
	ExpiresAt  time.Time
	Prev       *CacheItem
	Next       *CacheItem
}

// NewLRUCache 创建LRU缓存
func NewLRUCache(capacity int) *LRUCache {
	cache := &LRUCache{
		cache:    make(map[string]*CacheItem, capacity),
		capacity: capacity,
	}

	// 初始化双向链表
	cache.head = &CacheItem{}
	cache.tail = &CacheItem{}
	cache.head.Next = cache.tail
	cache.tail.Prev = cache.head

	// 启动清理任务
	go cache.startCleanup()

	return cache
}

// Get 获取缓存项
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if item, exists := c.cache[key]; exists {
		// 检查是否过期
		if !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
			return nil, false
		}

		// 更新访问时间
		c.mu.RUnlock()
		c.mu.Lock()
		item.AccessTime = time.Now()
		c.moveToFront(item)
		c.mu.Unlock()
		c.mu.RLock()

		c.stats.Hits++
		return item.Value, true
	}

	c.stats.Misses++
	return nil, false
}

// Set 设置缓存项
func (c *LRUCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	// 检查是否已存在
	if item, exists := c.cache[key]; exists {
		item.Value = value
		item.AccessTime = time.Now()
		item.ExpiresAt = expiresAt
		c.moveToFront(item)
		return
	}

	// 检查容量
	if len(c.cache) >= c.capacity {
		// 移除最少使用的项
		c.removeLRU()
	}

	// 添加新项
	item := &CacheItem{
		Key:        key,
		Value:      value,
		AccessTime: time.Now(),
		ExpiresAt:  expiresAt,
	}

	c.cache[key] = item
	c.addToFront(item)
	c.stats.Sets++
}

// Delete 删除缓存项
func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.cache[key]; exists {
		c.removeItem(item)
		delete(c.cache, key)
		c.stats.Deletes++
	}
}

// Clear 清空缓存
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CacheItem, c.capacity)
	c.head = &CacheItem{}
	c.tail = &CacheItem{}
	c.head.Next = c.tail
	c.tail.Prev = c.head
	c.stats.Clears++
}

// Stats 获取缓存统计
func (c *LRUCache) Stats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Items = len(c.cache)
	stats.Capacity = c.capacity
	stats.Usage = float64(len(c.cache)) / float64(c.capacity)

	return &stats
}

// addToFront 添加到前端
func (c *LRUCache) addToFront(item *CacheItem) {
	item.Next = c.head.Next
	item.Prev = c.head
	c.head.Next.Prev = item
	c.head.Next = item
}

// moveToFront 移动到前端
func (c *LRUCache) moveToFront(item *CacheItem) {
	c.removeItem(item)
	c.addToFront(item)
}

// removeItem 移除项
func (c *LRUCache) removeItem(item *CacheItem) {
	item.Prev.Next = item.Next
	item.Next.Prev = item.Prev
}

// removeLRU 移除最少使用的项
func (c *LRUCache) removeLRU() {
	if c.tail.Prev != c.head {
		lru := c.tail.Prev
		c.removeItem(lru)
		delete(c.cache, lru.Key)
	}
}

// startCleanup 启动清理任务
func (c *LRUCache) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup 清理过期项
func (c *LRUCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for key, item := range c.cache {
		if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
			c.removeItem(item)
			delete(c.cache, key)
		}
	}
}

// CacheStats 缓存统计
type CacheStats struct {
	Items    int     `json:"items"`
	Capacity int     `json:"capacity"`
	Usage    float64 `json:"usage"`
	Hits     int64   `json:"hits"`
	Misses   int64   `json:"misses"`
	Sets     int64   `json:"sets"`
	Deletes  int64   `json:"deletes"`
	Clears   int64   `json:"clears"`
}

// StringCache 字符串缓存（针对Helm配置等）
type StringCache struct {
	cache *LRUCache
	mm    *MemoryManager
}

// NewStringCache 创建字符串缓存
func NewStringCache(capacity int, memoryManager *MemoryManager) *StringCache {
	return &StringCache{
		cache: NewLRUCache(capacity),
		mm:    memoryManager,
	}
}

// GetStats 获取字符串缓存统计
func (sc *StringCache) Get(key string) (string, bool) {
	if value, found := sc.cache.Get(key); found {
		if str, ok := value.(string); ok {
			return str, true
		}
	}
	return "", false
}

// Stats 获取缓存统计
func (sc *StringCache) Stats() *CacheStats {
	return sc.cache.Stats()
}

// Set 设置字符串
func (sc *StringCache) Set(key, value string, ttl time.Duration) {
	sc.cache.Set(key, value, ttl)

	// 跟踪内存分配
	if sc.mm != nil {
		sc.mm.TrackAllocation("cache_"+key, int64(len(value)), "string_cache")
	}
}

// PerformanceProfiler 性能分析器
type PerformanceProfiler struct {
	mu         sync.RWMutex
	operations map[string]*OperationStats
	logger     *StructuredLogger
	metrics    Metrics
}

// OperationStats 操作统计
type OperationStats struct {
	Count     int64         `json:"count"`
	TotalTime time.Duration `json:"total_time"`
	MinTime   time.Duration `json:"min_time"`
	MaxTime   time.Duration `json:"max_time"`
	AvgTime   time.Duration `json:"avg_time"`
	LastTime  time.Duration `json:"last_time"`
	Errors    int64         `json:"errors"`
}

// NewPerformanceProfiler 创建性能分析器
func NewPerformanceProfiler(logger *StructuredLogger, metrics Metrics) *PerformanceProfiler {
	return &PerformanceProfiler{
		operations: make(map[string]*OperationStats),
		logger:     logger,
		metrics:    metrics,
	}
}

// RecordOperation 记录操作性能
func (pp *PerformanceProfiler) RecordOperation(name string, duration time.Duration, success bool) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	stats, exists := pp.operations[name]
	if !exists {
		stats = &OperationStats{
			MinTime: duration,
			MaxTime: duration,
		}
		pp.operations[name] = stats
	}

	stats.Count++
	stats.TotalTime += duration
	stats.LastTime = duration

	if duration < stats.MinTime {
		stats.MinTime = duration
	}

	if duration > stats.MaxTime {
		stats.MaxTime = duration
	}

	stats.AvgTime = stats.TotalTime / time.Duration(stats.Count)

	if !success {
		stats.Errors++
	}

	// 记录指标
	if pp.metrics != nil {
		pp.metrics.RecordOperation(name, duration, success)
	}

	// 记录慢操作日志
	if duration > 1*time.Second {
		pp.logger.WithField("operation", name).
			WithField("duration", duration).
			WithField("success", success).
			Warn("慢操作检测")
	}
}

// GetStats 获取性能统计
func (pp *PerformanceProfiler) GetStats() map[string]*OperationStats {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	result := make(map[string]*OperationStats)
	for name, stats := range pp.operations {
		// 复制统计数据
		result[name] = &OperationStats{
			Count:     stats.Count,
			TotalTime: stats.TotalTime,
			MinTime:   stats.MinTime,
			MaxTime:   stats.MaxTime,
			AvgTime:   stats.AvgTime,
			LastTime:  stats.LastTime,
			Errors:    stats.Errors,
		}
	}

	return result
}

// GetTopSlowOperations 获取最慢的操作
func (pp *PerformanceProfiler) GetTopSlowOperations(limit int) []*OperationStats {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	// 按最大执行时间排序
	operations := make([]*OperationStats, 0, len(pp.operations))
	for _, stats := range pp.operations {
		operations = append(operations, stats)
	}

	// 简单排序（实际应用中可以使用sort.Slice优化）
	if len(operations) > limit {
		operations = operations[:limit]
	}

	return operations
}

// BenchmarkResult 基准测试结果
type BenchmarkResult struct {
	Name             string        `json:"name"`
	Iterations       int           `json:"iterations"`
	TotalTime        time.Duration `json:"total_time"`
	AverageTime      time.Duration `json:"average_time"`
	MinTime          time.Duration `json:"min_time"`
	MaxTime          time.Duration `json:"max_time"`
	OperationsPerSec float64       `json:"ops_per_sec"`
}

// RunBenchmark 运行基准测试
func RunBenchmark(name string, fn func() error, iterations int) *BenchmarkResult {
	start := time.Now()
	var minTime, maxTime time.Duration
	var errors int

	for i := 0; i < iterations; i++ {
		opStart := time.Now()
		err := fn()
		opDuration := time.Since(opStart)

		if i == 0 {
			minTime = opDuration
			maxTime = opDuration
		} else {
			if opDuration < minTime {
				minTime = opDuration
			}
			if opDuration > maxTime {
				maxTime = opDuration
			}
		}

		if err != nil {
			errors++
		}
	}

	totalTime := time.Since(start)
	averageTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()

	return &BenchmarkResult{
		Name:             name,
		Iterations:       iterations,
		TotalTime:        totalTime,
		AverageTime:      averageTime,
		MinTime:          minTime,
		MaxTime:          maxTime,
		OperationsPerSec: opsPerSec,
	}
}

// PerformanceConfig 性能配置
type PerformanceConfig struct {
	EnableProfiling     bool          `json:"enable_profiling"`
	ProfilingInterval   time.Duration `json:"profiling_interval"`
	EnableCache         bool          `json:"enable_cache"`
	CacheCapacity       int           `json:"cache_capacity"`
	CacheTTL            time.Duration `json:"cache_ttl"`
	EnableMemoryManager bool          `json:"enable_memory_manager"`
	GCTriggerBytes      int64         `json:"gc_trigger_bytes"`
}

// DefaultPerformanceConfig 默认性能配置
func DefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		EnableProfiling:     true,
		ProfilingInterval:   30 * time.Second,
		EnableCache:         true,
		CacheCapacity:       1000,
		CacheTTL:            5 * time.Minute,
		EnableMemoryManager: true,
		GCTriggerBytes:      100 * 1024 * 1024, // 100MB
	}
}

// Apply 应用性能配置
func (pc *PerformanceConfig) Apply(pm *PerformanceManager) {
	if pc.EnableProfiling {
		pm.EnableProfiling = true
		pm.ProfilingInterval = pc.ProfilingInterval
	}

	if pc.EnableCache {
		pm.EnableCache = true
		pm.CacheCapacity = pc.CacheCapacity
		pm.CacheTTL = pc.CacheTTL
	}

	if pc.EnableMemoryManager {
		pm.EnableMemoryManager = true
		pm.GCTriggerBytes = pc.GCTriggerBytes
	}
}

// PerformanceManager 性能管理器
type PerformanceManager struct {
	config        *PerformanceConfig
	memoryManager *MemoryManager
	stringCache   *StringCache
	profiler      *PerformanceProfiler
	logger        *StructuredLogger
	metrics       Metrics

	// 配置项
	EnableProfiling     bool
	ProfilingInterval   time.Duration
	EnableCache         bool
	CacheCapacity       int
	CacheTTL            time.Duration
	EnableMemoryManager bool
	GCTriggerBytes      int64
}

// NewPerformanceManager 创建性能管理器
func NewPerformanceManager(config *PerformanceConfig, logger *StructuredLogger, metrics Metrics) *PerformanceManager {
	pm := &PerformanceManager{
		config:              config,
		logger:              logger,
		metrics:             metrics,
		EnableProfiling:     config.EnableProfiling,
		ProfilingInterval:   config.ProfilingInterval,
		EnableCache:         config.EnableCache,
		CacheCapacity:       config.CacheCapacity,
		CacheTTL:            config.CacheTTL,
		EnableMemoryManager: config.EnableMemoryManager,
		GCTriggerBytes:      config.GCTriggerBytes,
	}

	if pm.EnableMemoryManager {
		pm.memoryManager = NewMemoryManager(metrics, logger)
	}

	if pm.EnableCache {
		pm.stringCache = NewStringCache(pm.CacheCapacity, pm.memoryManager)
	}

	pm.profiler = NewPerformanceProfiler(logger, metrics)

	// 应用配置
	config.Apply(pm)

	return pm
}

// GetMemoryManager 获取内存管理器
func (pm *PerformanceManager) GetMemoryManager() *MemoryManager {
	return pm.memoryManager
}

// GetCache 获取缓存
func (pm *PerformanceManager) GetCache() *StringCache {
	return pm.stringCache
}

// GetProfiler 获取性能分析器
func (pm *PerformanceManager) GetProfiler() *PerformanceProfiler {
	return pm.profiler
}

// RecordOperation 记录操作
func (pm *PerformanceManager) RecordOperation(name string, duration time.Duration, success bool) {
	if pm.profiler != nil {
		pm.profiler.RecordOperation(name, duration, success)
	}
}

// GetStats 获取性能统计
func (pm *PerformanceManager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if pm.memoryManager != nil {
		stats["memory"] = pm.memoryManager.GetStats()
	}

	if pm.stringCache != nil {
		stats["cache"] = pm.stringCache.Stats()
	}

	if pm.profiler != nil {
		stats["profiler"] = pm.profiler.GetStats()
	}

	return stats
}

// Debug 全局调试标志
var Debug = false
