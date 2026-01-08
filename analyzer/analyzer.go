// Package analyzer provides CloudFormation stack analysis functionality
package analyzer

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// StackError represents an error found in CloudFormation stack events
type StackError struct {
	Timestamp                 time.Time
	ResourceType              string
	LogicalResourceId         string
	ResourceStatus            string
	ResourceStatusReason      string
	EventId                   string
	IsGeneralServiceException bool
}

// StackAnalysis contains the complete analysis results for a stack
type StackAnalysis struct {
	StackName      string
	AnalysisTime   time.Time
	Errors         []CorrelatedError
	GeneralErrors  int
	DetailedErrors int
}

// CorrelatedError represents a CloudFormation error with optional CloudTrail correlation
type CorrelatedError struct {
	StackError      StackError
	CloudTrailEvent *CloudTrailEvent
	DetailedMessage string
}

// CloudTrailEvent represents relevant CloudTrail log data
type CloudTrailEvent struct {
	EventTime        time.Time
	EventName        string
	EventSource      string
	UserIdentity     map[string]interface{}
	ResponseElements map[string]interface{}
	ErrorCode        string
	ErrorMessage     string
}

// AnalyzeStackErrors performs the main analysis workflow for a CloudFormation stack
func AnalyzeStackErrors(ctx context.Context, stackName string) (*StackAnalysis, error) {
	// TODO: Implement main analysis function
	return nil, nil
}

// GetStackEvents retrieves CloudFormation stack events
func GetStackEvents(ctx context.Context, stackName string) ([]types.StackEvent, error) {
	// TODO: Implement stack event retrieval
	return nil, nil
}