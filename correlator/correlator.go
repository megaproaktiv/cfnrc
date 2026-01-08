// Package correlator provides error correlation functionality between CloudFormation and CloudTrail
package correlator

import (
	"strings"
	"time"

	"cfn-root-cause/analyzer"
)

// DefaultTimeWindow is the default time window for correlating events (5 minutes)
const DefaultTimeWindow = 5 * time.Minute

// CorrelationConfig holds configuration for error correlation
type CorrelationConfig struct {
	// TimeWindow is the maximum time difference between CloudFormation and CloudTrail events
	// for them to be considered correlated
	TimeWindow time.Duration
}

// DefaultConfig returns the default correlation configuration
func DefaultConfig() CorrelationConfig {
	return CorrelationConfig{
		TimeWindow: DefaultTimeWindow,
	}
}

// CorrelateErrors matches CloudFormation errors with CloudTrail events.
// It returns a slice of CorrelatedError containing the original CloudFormation error,
// any matching CloudTrail event, and a detailed message extracted from CloudTrail.
// Uses the default time window for correlation.
func CorrelateErrors(cfnErrors []analyzer.StackError, trailEvents []analyzer.CloudTrailEvent) []analyzer.CorrelatedError {
	return CorrelateErrorsWithConfig(cfnErrors, trailEvents, DefaultConfig())
}

// CorrelateErrorsWithConfig matches CloudFormation errors with CloudTrail events
// using the provided configuration.
func CorrelateErrorsWithConfig(cfnErrors []analyzer.StackError, trailEvents []analyzer.CloudTrailEvent, config CorrelationConfig) []analyzer.CorrelatedError {
	if len(cfnErrors) == 0 {
		return []analyzer.CorrelatedError{}
	}

	correlatedErrors := make([]analyzer.CorrelatedError, 0, len(cfnErrors))

	for _, cfnError := range cfnErrors {
		correlated := analyzer.CorrelatedError{
			StackError:      cfnError,
			DetailedMessage: cfnError.ResourceStatusReason, // Preserve original context
		}

		// Find matching CloudTrail event
		matchingEvent := FindMatchingTrailEventWithConfig(cfnError, trailEvents, config)
		if matchingEvent != nil {
			correlated.CloudTrailEvent = matchingEvent
			// Extract detailed message from CloudTrail if available
			detailedMsg := extractDetailedMessage(*matchingEvent)
			if detailedMsg != "" {
				correlated.DetailedMessage = detailedMsg
			}
		}

		correlatedErrors = append(correlatedErrors, correlated)
	}

	return correlatedErrors
}

// FindMatchingTrailEvent finds a specific CloudTrail event that matches a CloudFormation error.
// It uses the default time window for matching.
func FindMatchingTrailEvent(cfnError analyzer.StackError, trailEvents []analyzer.CloudTrailEvent) *analyzer.CloudTrailEvent {
	return FindMatchingTrailEventWithConfig(cfnError, trailEvents, DefaultConfig())
}

// FindMatchingTrailEventWithConfig finds a CloudTrail event that matches a CloudFormation error
// using the provided configuration.
// Matching is based on:
// 1. Timestamp proximity (within the configured time window)
// 2. Resource identifier matching (logical resource ID in event source/name)
// 3. Presence of error information in the CloudTrail event
func FindMatchingTrailEventWithConfig(cfnError analyzer.StackError, trailEvents []analyzer.CloudTrailEvent, config CorrelationConfig) *analyzer.CloudTrailEvent {
	if len(trailEvents) == 0 {
		return nil
	}

	var bestMatch *analyzer.CloudTrailEvent
	var bestScore int
	var bestTimeDiff time.Duration = config.TimeWindow + 1 // Initialize to beyond window

	for i := range trailEvents {
		event := &trailEvents[i]

		// Check timestamp proximity
		timeDiff := absTimeDiff(cfnError.Timestamp, event.EventTime)
		if timeDiff > config.TimeWindow {
			continue
		}

		// Calculate match score
		score := calculateMatchScore(cfnError, *event)
		if score == 0 {
			continue
		}

		// Prefer higher score, or closer timestamp if scores are equal
		if score > bestScore || (score == bestScore && timeDiff < bestTimeDiff) {
			bestMatch = event
			bestScore = score
			bestTimeDiff = timeDiff
		}
	}

	return bestMatch
}

// calculateMatchScore calculates a score indicating how well a CloudTrail event
// matches a CloudFormation error. Higher scores indicate better matches.
func calculateMatchScore(cfnError analyzer.StackError, trailEvent analyzer.CloudTrailEvent) int {
	score := 0

	// Must have error information to be a valid match
	if !hasErrorInformation(trailEvent) {
		return 0
	}

	// Base score for having error information
	score += 1

	// Check resource identifier match
	if matchesResourceIdentifier(cfnError, trailEvent) {
		score += 3
	}

	// Check resource type match (event source often contains service name)
	if matchesResourceType(cfnError, trailEvent) {
		score += 2
	}

	return score
}

// matchesResourceIdentifier checks if the CloudTrail event is related to the
// CloudFormation resource by comparing identifiers
func matchesResourceIdentifier(cfnError analyzer.StackError, trailEvent analyzer.CloudTrailEvent) bool {
	if cfnError.LogicalResourceId == "" {
		return false
	}

	resourceId := strings.ToLower(cfnError.LogicalResourceId)

	// Check if resource ID appears in event name
	if strings.Contains(strings.ToLower(trailEvent.EventName), resourceId) {
		return true
	}

	// Check if resource ID appears in error message
	if strings.Contains(strings.ToLower(trailEvent.ErrorMessage), resourceId) {
		return true
	}

	// Check responseElements for resource references
	if trailEvent.ResponseElements != nil {
		for _, value := range trailEvent.ResponseElements {
			if strVal, ok := value.(string); ok {
				if strings.Contains(strings.ToLower(strVal), resourceId) {
					return true
				}
			}
		}
	}

	return false
}

// matchesResourceType checks if the CloudTrail event source matches the
// CloudFormation resource type
func matchesResourceType(cfnError analyzer.StackError, trailEvent analyzer.CloudTrailEvent) bool {
	if cfnError.ResourceType == "" || trailEvent.EventSource == "" {
		return false
	}

	// Extract service name from CloudFormation resource type (e.g., "AWS::Lambda::Function" -> "lambda")
	resourceType := strings.ToLower(cfnError.ResourceType)
	eventSource := strings.ToLower(trailEvent.EventSource)

	// CloudFormation resource types are like "AWS::ServiceName::ResourceType"
	parts := strings.Split(resourceType, "::")
	if len(parts) >= 2 {
		serviceName := strings.ToLower(parts[1])
		// CloudTrail event sources are like "servicename.amazonaws.com"
		if strings.Contains(eventSource, serviceName) {
			return true
		}
	}

	return false
}

// hasErrorInformation checks if a CloudTrail event contains error information
func hasErrorInformation(event analyzer.CloudTrailEvent) bool {
	if event.ErrorCode != "" || event.ErrorMessage != "" {
		return true
	}

	if event.ResponseElements != nil {
		msg := extractMessageFromResponseElements(event.ResponseElements)
		return msg != ""
	}

	return false
}

// extractDetailedMessage extracts the most detailed error message from a CloudTrail event
func extractDetailedMessage(event analyzer.CloudTrailEvent) string {
	// First, check the direct error message field
	if event.ErrorMessage != "" {
		return event.ErrorMessage
	}

	// Try to extract from responseElements
	if event.ResponseElements != nil {
		if msg := extractMessageFromResponseElements(event.ResponseElements); msg != "" {
			return msg
		}
	}

	// Fall back to error code if available
	if event.ErrorCode != "" {
		return "Error code: " + event.ErrorCode
	}

	return ""
}

// extractMessageFromResponseElements extracts the message field from responseElements
func extractMessageFromResponseElements(responseElements map[string]interface{}) string {
	if responseElements == nil {
		return ""
	}

	// Try direct "message" field (lowercase)
	if msg, ok := responseElements["message"].(string); ok && msg != "" {
		return msg
	}

	// Try "Message" field (capitalized)
	if msg, ok := responseElements["Message"].(string); ok && msg != "" {
		return msg
	}

	// Try nested "error" object with "message" field
	if errorObj, ok := responseElements["error"].(map[string]interface{}); ok {
		if msg, ok := errorObj["message"].(string); ok && msg != "" {
			return msg
		}
		if msg, ok := errorObj["Message"].(string); ok && msg != "" {
			return msg
		}
	}

	// Try nested "Error" object (capitalized)
	if errorObj, ok := responseElements["Error"].(map[string]interface{}); ok {
		if msg, ok := errorObj["message"].(string); ok && msg != "" {
			return msg
		}
		if msg, ok := errorObj["Message"].(string); ok && msg != "" {
			return msg
		}
	}

	return ""
}

// absTimeDiff returns the absolute time difference between two times
func absTimeDiff(t1, t2 time.Time) time.Duration {
	diff := t1.Sub(t2)
	if diff < 0 {
		return -diff
	}
	return diff
}

// FilterErrorEvents filters CloudTrail events to only include those with error information
func FilterErrorEvents(events []analyzer.CloudTrailEvent) []analyzer.CloudTrailEvent {
	var errorEvents []analyzer.CloudTrailEvent
	for _, event := range events {
		if hasErrorInformation(event) {
			errorEvents = append(errorEvents, event)
		}
	}
	return errorEvents
}

// GetCorrelationSummary returns a summary of the correlation results
func GetCorrelationSummary(correlatedErrors []analyzer.CorrelatedError) (total, withCloudTrail, generalServiceExceptions int) {
	total = len(correlatedErrors)
	for _, err := range correlatedErrors {
		if err.CloudTrailEvent != nil {
			withCloudTrail++
		}
		if err.StackError.IsGeneralServiceException {
			generalServiceExceptions++
		}
	}
	return
}