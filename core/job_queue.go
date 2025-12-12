package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JobState 作业状态
type JobState string

const (
	JobStatePending   JobState = "pending"   // 等待中
	JobStateRunning   JobState = "running"   // 运行中
	JobStateCompleted JobState = "completed" // 完成
	JobStateFailed    JobState = "failed"    // 失败
	JobStateCancelled JobState = "cancelled" // 取消
)

// JobPriority 作业优先级
type JobPriority int

const (
	PriorityLow    JobPriority = iota // 低优先级
	PriorityNormal                    // 普通优先级
	PriorityHigh                      // 高优先级
)

// JobProcessor 作业处理器接口
type JobProcessor interface {
	Process()
	GetPriority() int
}

// JobItem 作业项结构体
type JobItem struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`       // 作业类型: deploy, upgrade, uninstall
	Name       string                 `json:"name"`       // 应用名称
	Namespace  string                 `json:"namespace"`  // 命名空间
	ProjectID  string                 `json:"project_id"` // 项目ID
	Priority   JobPriority            `json:"priority"`   // 优先级
	State      JobState               `json:"state"`      // 状态
	CreatedAt  time.Time              `json:"created_at"`
	StartedAt  *time.Time             `json:"started_at,omitempty"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
	Progress   int                    `json:"progress"` // 进度百分比
	Context    context.Context        `json:"-"`        // 上下文，用于取消
	Cancel     context.CancelFunc     `json:"-"`        // 取消函数
	Data       map[string]interface{} `json:"data"`     // 作业数据
	Result     *JobResult             `json:"result"`   // 作业结果
	mu         sync.RWMutex           `json:"-"`        // 保护状态字段
}

// Process 实现 JobProcessor 接口
func (j *JobItem) Process() {
	// JobItem默认实现为空，子类需要重写
}

// GetPriority 实现 JobProcessor 接口
func (j *JobItem) GetPriority() int {
	return int(j.Priority)
}

// JobResult 作业结果
type JobResult struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
	Error   error                  `json:"error,omitempty"`
}

// JobQueue 作业队列
type JobQueue struct {
	queues     map[JobPriority]chan JobProcessor // 按优先级的队列
	workers    int                               // 工作协程数量
	ctx        context.Context                   // 上下文
	cancel     context.CancelFunc                // 取消函数
	wg         sync.WaitGroup                    // 等待组
	logger     *zap.Logger                       // 日志
	activeJobs map[string]JobProcessor           // 活跃作业映射
	mu         sync.RWMutex                      // 保护活跃作业映射
}

// NewJobQueue 创建新的作业队列
func NewJobQueue(workers int, logger *zap.Logger) *JobQueue {
	if workers <= 0 {
		workers = 3 // 默认工作协程数
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 创建不同优先级的队列
	queues := map[JobPriority]chan JobProcessor{
		PriorityHigh:   make(chan JobProcessor, 100),
		PriorityNormal: make(chan JobProcessor, 200),
		PriorityLow:    make(chan JobProcessor, 300),
	}

	q := &JobQueue{
		queues:     queues,
		workers:    workers,
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
		activeJobs: make(map[string]JobProcessor),
	}

	// 启动工作协程
	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go q.worker(fmt.Sprintf("worker-%d", i))
	}

	return q
}

// Submit 提交作业
func (q *JobQueue) Submit(job JobProcessor) error {
	select {
	case <-q.ctx.Done():
		return fmt.Errorf("队列已关闭")
	default:
	}

	// 如果作业是 JobItem 类型，设置初始状态
	if jobItem, ok := job.(*JobItem); ok {
		jobItem.State = JobStatePending
		jobItem.CreatedAt = time.Now()
		jobItem.Context, jobItem.Cancel = context.WithCancel(q.ctx)

		// 添加到活跃作业映射
		q.mu.Lock()
		q.activeJobs[jobItem.ID] = job
		q.mu.Unlock()

		// 根据优先级选择队列
		select {
		case q.queues[JobPriority(job.GetPriority())] <- job:
			q.logger.Info("作业已提交",
				zap.String("job_id", jobItem.ID),
				zap.String("type", jobItem.Type),
				zap.String("name", jobItem.Name),
				zap.String("priority", fmt.Sprintf("%d", jobItem.Priority)))
			return nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("队列已满，作业提交超时")
		}
	}

	// 对于其他类型的作业，直接提交到默认队列
	select {
	case q.queues[PriorityNormal] <- job:
		q.logger.Info("作业已提交（默认队列）")
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("队列已满，作业提交超时")
	}
}

// GetJob 获取作业状态
func (q *JobQueue) GetJob(jobID string) (JobProcessor, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	job, exists := q.activeJobs[jobID]
	if !exists {
		return nil, false
	}

	return job, true
}

// ListJobs 列出所有活跃作业
func (q *JobQueue) ListJobs() []JobProcessor {
	q.mu.RLock()
	defer q.mu.RUnlock()

	jobs := make([]JobProcessor, 0, len(q.activeJobs))
	for _, job := range q.activeJobs {
		jobs = append(jobs, job)
	}

	return jobs
}

// CancelJob 取消作业
func (q *JobQueue) CancelJob(jobID string) error {
	q.mu.RLock()
	job, exists := q.activeJobs[jobID]
	q.mu.RUnlock()

	if !exists {
		return fmt.Errorf("作业不存在: %s", jobID)
	}

	// 如果作业是 JobItem 类型，检查状态和取消
	if jobItem, ok := job.(*JobItem); ok {
		// 检查作业状态
		jobItem.mu.RLock()
		state := jobItem.State
		jobItem.mu.RUnlock()

		if state == JobStateCompleted || state == JobStateFailed || state == JobStateCancelled {
			return fmt.Errorf("作业已结束，无法取消: %s", jobID)
		}

		// 取消作业
		if jobItem.Cancel != nil {
			jobItem.Cancel()
		}

		jobItem.mu.Lock()
		jobItem.State = JobStateCancelled
		now := time.Now()
		jobItem.FinishedAt = &now
		jobItem.mu.Unlock()

		return nil
	}

	return fmt.Errorf("不支持的作业类型")
}

// Close 关闭队列
func (q *JobQueue) Close() {
	q.cancel()

	// 关闭所有队列
	for _, ch := range q.queues {
		close(ch)
	}

	// 等待所有工作协程结束
	q.wg.Wait()

	q.logger.Info("作业队列已关闭")
}

// worker 工作协程
func (q *JobQueue) worker(name string) {
	defer q.wg.Done()

	for {
		select {
		case <-q.ctx.Done():
			q.logger.Info("工作协程退出", zap.String("worker", name))
			return
		case job := <-q.queues[PriorityHigh]:
			q.processJob(job, name)
		case job := <-q.queues[PriorityNormal]:
			q.processJob(job, name)
		case job := <-q.queues[PriorityLow]:
			q.processJob(job, name)
		case <-time.After(1 * time.Second):
			// 避免忙等
			continue
		}
	}
}

// processJob 处理作业
func (q *JobQueue) processJob(job JobProcessor, workerName string) {
	// 如果作业是 JobItem 类型，更新状态
	var jobItem *JobItem
	var jobID string

	if item, ok := job.(*JobItem); ok {
		jobItem = item
		jobID = item.ID

		// 更新作业状态
		item.mu.Lock()
		item.State = JobStateRunning
		now := time.Now()
		item.StartedAt = &now
		item.Progress = 0
		item.mu.Unlock()

		q.logger.Info("开始处理作业",
			zap.String("job_id", item.ID),
			zap.String("worker", workerName),
			zap.String("type", item.Type),
			zap.String("name", item.Name))
	} else {
		q.logger.Info("开始处理作业",
			zap.String("worker", workerName))
		jobID = fmt.Sprintf("job-%p", job)
	}

	// 执行作业
	err := q.executeJob(job)

	// 如果是 JobItem 类型，更新最终状态
	if jobItem != nil {
		jobItem.mu.Lock()
		defer jobItem.mu.Unlock()

		if err != nil {
			jobItem.State = JobStateFailed
			jobItem.Result = &JobResult{
				Success: false,
				Message: "作业执行失败",
				Error:   err,
			}
			q.logger.Error("作业执行失败",
				zap.String("job_id", jobID),
				zap.Error(err),
				zap.String("worker", workerName))
		} else {
			jobItem.State = JobStateCompleted
			jobItem.Progress = 100
			jobItem.Result = &JobResult{
				Success: true,
				Message: "作业执行成功",
			}
			q.logger.Info("作业执行成功",
				zap.String("job_id", jobID),
				zap.String("worker", workerName))
		}

		now := time.Now()
		jobItem.FinishedAt = &now

		// 从活跃作业映射中移除
		q.mu.Lock()
		delete(q.activeJobs, jobID)
		q.mu.Unlock()
	}
}

// executeJob 执行具体作业
func (q *JobQueue) executeJob(job JobProcessor) error {
	// 如果作业是 JobItem 类型，根据类型执行不同的操作
	if jobItem, ok := job.(*JobItem); ok {
		switch jobItem.Type {
		case "deploy":
			return q.executeDeploy(jobItem)
		case "upgrade":
			return q.executeUpgrade(jobItem)
		case "uninstall":
			return q.executeUninstall(jobItem)
		default:
			return fmt.Errorf("未知的作业类型: %s", jobItem.Type)
		}
	}

	// 对于其他类型的作业，直接调用Process方法
	job.Process()
	return nil
}

// executeDeploy 执行部署作业
func (q *JobQueue) executeDeploy(job *JobItem) error {
	// 这里应该集成具体的Helm部署逻辑
	// 现在只是示例实现

	// 模拟部署过程
	steps := []string{"准备环境", "下载Chart", "渲染模板", "部署资源", "验证状态"}

	for i, step := range steps {
		// 检查是否被取消
		select {
		case <-job.Context.Done():
			return fmt.Errorf("作业被取消")
		default:
		}

		// 更新进度
		progress := (i + 1) * 100 / len(steps)
		job.mu.Lock()
		job.Progress = progress
		job.mu.Unlock()

		q.logger.Info("部署进度",
			zap.String("job_id", job.ID),
			zap.String("step", step),
			zap.Int("progress", progress))

		// 模拟步骤执行时间
		time.Sleep(2 * time.Second)
	}

	return nil
}

// executeUpgrade 执行升级作业
func (q *JobQueue) executeUpgrade(job *JobItem) error {
	// 模拟升级过程
	job.mu.Lock()
	job.Progress = 50
	job.mu.Unlock()

	time.Sleep(3 * time.Second)

	job.mu.Lock()
	job.Progress = 100
	job.mu.Unlock()

	return nil
}

// executeUninstall 执行卸载作业
func (q *JobQueue) executeUninstall(job *JobItem) error {
	// 模拟卸载过程
	job.mu.Lock()
	job.Progress = 30
	job.mu.Unlock()

	time.Sleep(1 * time.Second)

	job.mu.Lock()
	job.Progress = 100
	job.mu.Unlock()

	return nil
}

// GetStats 获取队列统计信息
func (q *JobQueue) GetStats() map[string]interface{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_jobs"] = len(q.activeJobs)
	stats["queue_lengths"] = make(map[string]int)

	for priority, jobs := range q.queues {
		priorityStr := fmt.Sprintf("%d", priority)
		stats["queue_lengths"].(map[string]int)[priorityStr] = len(jobs)
	}

	return stats
}
