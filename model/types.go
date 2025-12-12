package model

// RancherRequest 请求体
type RancherRequest struct {
	Prune           bool              `json:"prune"`
	Timeout         int               `json:"timeout"`
	Wait            bool              `json:"wait"`
	Type            string            `json:"type"`
	Name            string            `json:"name" binding:"required"`
	Answers         map[string]string `json:"answers"`
	TargetNamespace string            `json:"targetNamespace" binding:"required"`
	ExternalID      string            `json:"externalId" binding:"required"`
	ProjectID       string            `json:"projectId"`
	ValuesYaml      string            `json:"valuesYaml"`
}

// RancherResponse 响应体
type RancherResponse struct {
	ID                   string            `json:"id"`
	BaseType             string            `json:"baseType"`
	Name                 string            `json:"name"`
	State                string            `json:"state"`
	TargetNamespace      string            `json:"targetNamespace"`
	ExternalID           string            `json:"externalId"`
	Type                 string            `json:"type"`
	Links                map[string]string `json:"links"`
	Answers              map[string]string `json:"answers"`
	Created              string            `json:"created"`
	ProjectID            string            `json:"projectId"`
	Prune                bool              `json:"prune"`
	Timeout              int               `json:"timeout"`
	Wait                 bool              `json:"wait"`
	ValuesYaml           string            `json:"valuesYaml"`
	Labels               map[string]string `json:"labels,omitempty"`
	Annotations          map[string]string `json:"annotations,omitempty"`
	UUID                 string            `json:"uuid,omitempty"`
	CreatorID            string            `json:"creatorId,omitempty"`
	Transitioning        string            `json:"transitioning,omitempty"`
	TransitioningMessage string            `json:"transitioningMessage,omitempty"`
	AppRevisionID        string            `json:"appRevisionId,omitempty"`
	MultiClusterAppID    string            `json:"multiClusterAppId,omitempty"`
	NamespaceID          string            `json:"namespaceId,omitempty"`
	CreatedTS            int64             `json:"createdTS,omitempty"`
	ActionLinks          map[string]string `json:"actionLinks,omitempty"`
}

// ErrorResponse 错误响应
type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    string `json:"code"`
}
