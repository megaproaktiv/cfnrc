// Package extractor provides error extraction and categorization from CloudFormation stack events
package extractor

import (
	"strings"
	"time"

	"cfn-root-cause/analyzer"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// failedStatuses contains CloudFormation resource statuses that indicate errors
var failedStatuses = map[types.ResourceStatus]bool{
	types.ResourceStatusCreateFailed:         true,
	types.ResourceStatusDeleteFailed:         true,
	types.ResourceStatusUpdateFailed:         true,
	types.ResourceStatusImportFailed:         true,
	types.ResourceStatusImportRollbackFailed: true,
	types.ResourceStatusRollbackFailed:       true,
}

// generalServiceExceptionPatterns contains patterns that indicate a GeneralServiceException
var generalServiceExceptionPatterns = []string{
	"GeneralServiceException",
	"General Service Exception",
	"Internal Failure",
	"InternalFailure",
	"Service returned error",
}

// ExtractErrors extracts and categorizes errors from CloudFormation stack events.
// It identifies all events with failed statuses and flags GeneralServiceException errors.
func ExtractErrors(events []types.StackEvent) []analyzer.StackError {
	var errors []analyzer.StackError

	for _, event := range events {
		if !isFailedStatus(event.ResourceStatus) {
			continue
		}

		stackError := analyzer.StackError{
			Timestamp:            safeTime(event.Timestamp),
			ResourceType:         safeString(event.ResourceType),
			LogicalResourceId:    safeString(event.LogicalResourceId),
			ResourceStatus:       string(event.ResourceStatus),
			ResourceStatusReason: safeString(event.ResourceStatusReason),
			EventId:              safeString(event.EventId),
		}

		// Check if this is a GeneralServiceException that needs CloudTrail investigation
		stackError.IsGeneralServiceException = IsGeneralServiceException(stackError)

		errors = append(errors, stackError)
	}

	return errors
}

// IsGeneralServiceException identifies generic errors that need CloudTrail investigation.
// These are errors where CloudFormation doesn't provide detailed information and
// CloudTrail logs must be consulted for the root cause.
func IsGeneralServiceException(err analyzer.StackError) bool {
	reason := err.ResourceStatusReason
	if reason == "" {
		return false
	}

	reasonLower := strings.ToLower(reason)
	for _, pattern := range generalServiceExceptionPatterns {
		if strings.Contains(reasonLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isFailedStatus checks if a resource status indicates a failure
func isFailedStatus(status types.ResourceStatus) bool {
	return failedStatuses[status]
}

// safeString safely dereferences a string pointer, returning empty string if nil
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// safeTime safely dereferences a time pointer, returning zero time if nil
func safeTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}