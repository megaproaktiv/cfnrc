// Package cloudtrail provides CloudTrail log querying and analysis functionality
package cloudtrail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cfn-root-cause/analyzer"
	"cfn-root-cause/awserrors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// TimeRange represents a time period for CloudTrail queries
type TimeRange struct {
	StartTime time.Time
	EndTime   time.Time
}

// Client wraps the AWS CloudTrail client with additional functionality
type Client struct {
	ct *cloudtrail.Client
}

// CloudTrailAPI defines the interface for CloudTrail operations
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// NewClient creates a new CloudTrail client using default AWS configuration
// It uses standard AWS credential resolution (environment variables, profiles, IAM roles)
// Requirements: 6.2, 6.4
func NewClient(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		// Parse and return user-friendly error message for credential/config issues
		awsErr := awserrors.ParseAWSError(err, "CloudTrail")
		return nil, awsErr
	}

	return &Client{
		ct: cloudtrail.NewFromConfig(cfg),
	}, nil
}

// NewClientWithConfig creates a new CloudTrail client with a custom AWS config
func NewClientWithConfig(cfg aws.Config) *Client {
	return &Client{
		ct: cloudtrail.NewFromConfig(cfg),
	}
}


// SearchCloudTrailEvents queries CloudTrail logs for events in the specified time range.
// It searches for events related to CloudFormation operations and returns matching events.
// The filters parameter can contain resource names or event names to narrow the search.
// If filters is nil or empty, it searches by time range only.
func (c *Client) SearchCloudTrailEvents(ctx context.Context, timeRange TimeRange, filters []string) ([]analyzer.CloudTrailEvent, error) {
	var allEvents []analyzer.CloudTrailEvent
	var nextToken *string

	// If no filters provided, search by time range only
	if len(filters) == 0 {
		for {
			input := &cloudtrail.LookupEventsInput{
				StartTime:  aws.Time(timeRange.StartTime),
				EndTime:    aws.Time(timeRange.EndTime),
				NextToken:  nextToken,
				MaxResults: aws.Int32(50),
			}

			output, err := c.ct.LookupEvents(ctx, input)
			if err != nil {
				awsErr := awserrors.ParseAWSError(err, "CloudTrail")
				return nil, fmt.Errorf("failed to lookup CloudTrail events: %w", awsErr)
			}

			for _, event := range output.Events {
				ctEvent, err := parseCloudTrailEvent(event)
				if err != nil {
					continue
				}
				allEvents = append(allEvents, ctEvent)
			}

			if output.NextToken == nil {
				break
			}
			nextToken = output.NextToken
		}
		return allEvents, nil
	}

	// Build lookup attributes from filters
	var lookupAttributes []types.LookupAttribute
	for _, filter := range filters {
		// Add resource name filter
		lookupAttributes = append(lookupAttributes, types.LookupAttribute{
			AttributeKey:   types.LookupAttributeKeyResourceName,
			AttributeValue: aws.String(filter),
		})
	}

	// CloudTrail only allows one lookup attribute at a time
	// If we have filters, we need to make separate calls for each
	for {
		input := &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(timeRange.StartTime),
			EndTime:   aws.Time(timeRange.EndTime),
			NextToken: nextToken,
			MaxResults: aws.Int32(50),
		}

		// Use the first filter for this query
		input.LookupAttributes = []types.LookupAttribute{lookupAttributes[0]}

		output, err := c.ct.LookupEvents(ctx, input)
		if err != nil {
			// Parse and return user-friendly error message
			awsErr := awserrors.ParseAWSError(err, "CloudTrail")
			return nil, fmt.Errorf("failed to lookup CloudTrail events: %w", awsErr)
		}

		// Convert CloudTrail events to our internal format
		for _, event := range output.Events {
			ctEvent, err := parseCloudTrailEvent(event)
			if err != nil {
				// Log warning but continue processing other events
				continue
			}
			allEvents = append(allEvents, ctEvent)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allEvents, nil
}

// SearchByEventName queries CloudTrail logs for events with a specific event name
func (c *Client) SearchByEventName(ctx context.Context, timeRange TimeRange, eventName string) ([]analyzer.CloudTrailEvent, error) {
	var allEvents []analyzer.CloudTrailEvent
	var nextToken *string

	for {
		input := &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(timeRange.StartTime),
			EndTime:   aws.Time(timeRange.EndTime),
			NextToken: nextToken,
			MaxResults: aws.Int32(50),
			LookupAttributes: []types.LookupAttribute{
				{
					AttributeKey:   types.LookupAttributeKeyEventName,
					AttributeValue: aws.String(eventName),
				},
			},
		}

		output, err := c.ct.LookupEvents(ctx, input)
		if err != nil {
			// Parse and return user-friendly error message
			awsErr := awserrors.ParseAWSError(err, "CloudTrail")
			return nil, fmt.Errorf("failed to lookup CloudTrail events by event name: %w", awsErr)
		}

		for _, event := range output.Events {
			ctEvent, err := parseCloudTrailEvent(event)
			if err != nil {
				continue
			}
			allEvents = append(allEvents, ctEvent)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allEvents, nil
}

// SearchByUsername queries CloudTrail logs for events by a specific username
func (c *Client) SearchByUsername(ctx context.Context, timeRange TimeRange, username string) ([]analyzer.CloudTrailEvent, error) {
	var allEvents []analyzer.CloudTrailEvent
	var nextToken *string

	for {
		input := &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(timeRange.StartTime),
			EndTime:   aws.Time(timeRange.EndTime),
			NextToken: nextToken,
			MaxResults: aws.Int32(50),
			LookupAttributes: []types.LookupAttribute{
				{
					AttributeKey:   types.LookupAttributeKeyUsername,
					AttributeValue: aws.String(username),
				},
			},
		}

		output, err := c.ct.LookupEvents(ctx, input)
		if err != nil {
			// Parse and return user-friendly error message
			awsErr := awserrors.ParseAWSError(err, "CloudTrail")
			return nil, fmt.Errorf("failed to lookup CloudTrail events by username: %w", awsErr)
		}

		for _, event := range output.Events {
			ctEvent, err := parseCloudTrailEvent(event)
			if err != nil {
				continue
			}
			allEvents = append(allEvents, ctEvent)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allEvents, nil
}

// SearchForStackErrors queries CloudTrail for events related to CloudFormation stack errors.
// It searches around the error timestamp with a buffer to find related API calls.
// For better correlation, it searches by service type and CloudFormation user rather than logical resource ID,
// since CloudTrail records physical AWS API calls, not CloudFormation logical IDs.
func (c *Client) SearchForStackErrors(ctx context.Context, stackError analyzer.StackError) ([]analyzer.CloudTrailEvent, error) {
	// Create a time range around the error timestamp
	// Search 10 minutes before and after the error for better coverage
	timeRange := TimeRange{
		StartTime: stackError.Timestamp.Add(-10 * time.Minute),
		EndTime:   stackError.Timestamp.Add(10 * time.Minute),
	}

	// Extract service name from resource type (e.g., "AWS::Wisdom::AIPrompt" -> "qconnect")
	serviceName := extractServiceName(stackError.ResourceType)
	
	// Search for events by username (CloudFormation) to narrow down results
	// CloudFormation makes API calls on behalf of the stack
	events, err := c.SearchByUsername(ctx, timeRange, "AWSCloudFormation")
	if err != nil {
		return nil, err
	}
	
	// Filter events to match the service type
	var allEvents []analyzer.CloudTrailEvent
	if serviceName != "" {
		for _, event := range events {
			if matchesService(event, serviceName) {
				allEvents = append(allEvents, event)
			}
		}
	} else {
		// If we can't extract service name, return all CloudFormation events in time range
		allEvents = events
	}

	return allEvents, nil
}

// extractServiceName extracts the service name from a CloudFormation resource type
// e.g., "AWS::Wisdom::AIPrompt" -> "qconnect" (Wisdom service is called qconnect in CloudTrail)
// e.g., "AWS::Lambda::Function" -> "lambda"
func extractServiceName(resourceType string) string {
	parts := strings.Split(resourceType, "::")
	if len(parts) >= 2 {
		serviceName := strings.ToLower(parts[1])
		
		// Handle special cases where CloudFormation name differs from CloudTrail event source
		switch serviceName {
		case "wisdom":
			return "qconnect" // AWS Wisdom is called qconnect in CloudTrail
		default:
			return serviceName
		}
	}
	return ""
}

// matchesService checks if a CloudTrail event is from the specified AWS service
func matchesService(event analyzer.CloudTrailEvent, serviceName string) bool {
	// CloudTrail event sources are like "wisdom.amazonaws.com"
	eventSource := strings.ToLower(event.EventSource)
	return strings.Contains(eventSource, strings.ToLower(serviceName))
}


// parseCloudTrailEvent converts an AWS CloudTrail event to our internal format
func parseCloudTrailEvent(event types.Event) (analyzer.CloudTrailEvent, error) {
	ctEvent := analyzer.CloudTrailEvent{
		EventTime:   safeTime(event.EventTime),
		EventName:   safeString(event.EventName),
		EventSource: safeString(event.EventSource),
	}

	// Parse the CloudTrailEvent JSON to extract detailed information
	if event.CloudTrailEvent != nil {
		var eventData map[string]interface{}
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &eventData); err != nil {
			return ctEvent, fmt.Errorf("failed to parse CloudTrail event JSON: %w", err)
		}

		// Extract userIdentity
		if userIdentity, ok := eventData["userIdentity"].(map[string]interface{}); ok {
			ctEvent.UserIdentity = userIdentity
		}

		// Extract responseElements
		if responseElements, ok := eventData["responseElements"].(map[string]interface{}); ok {
			ctEvent.ResponseElements = responseElements
		}

		// Extract error information
		if errorCode, ok := eventData["errorCode"].(string); ok {
			ctEvent.ErrorCode = errorCode
		}
		if errorMessage, ok := eventData["errorMessage"].(string); ok {
			ctEvent.ErrorMessage = errorMessage
		}
	}

	return ctEvent, nil
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

// GetUnderlyingClient returns the underlying AWS CloudTrail client
// This is useful when direct access to the AWS SDK client is needed
func (c *Client) GetUnderlyingClient() *cloudtrail.Client {
	return c.ct
}


// ExtractResponseElements parses responseElements from a CloudTrail event.
// It returns the responseElements map if present, or an empty map if not available.
func ExtractResponseElements(event analyzer.CloudTrailEvent) (map[string]interface{}, error) {
	if event.ResponseElements == nil {
		return make(map[string]interface{}), nil
	}
	return event.ResponseElements, nil
}

// ExtractMessageFromResponseElements extracts the message field from responseElements.
// It handles various formats where the message might be stored:
// - Direct "message" field
// - Nested "error.message" field
// - "Message" field (capitalized)
// Returns empty string if no message is found.
func ExtractMessageFromResponseElements(responseElements map[string]interface{}) string {
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

// GetDetailedErrorMessage extracts the most detailed error message available from a CloudTrail event.
// It checks multiple sources in order of preference:
// 1. ErrorMessage field directly on the event
// 2. Message from responseElements
// 3. ErrorCode as fallback
func GetDetailedErrorMessage(event analyzer.CloudTrailEvent) string {
	// First, check the direct error message field
	if event.ErrorMessage != "" {
		return event.ErrorMessage
	}

	// Try to extract from responseElements
	if event.ResponseElements != nil {
		if msg := ExtractMessageFromResponseElements(event.ResponseElements); msg != "" {
			return msg
		}
	}

	// Fall back to error code if available
	if event.ErrorCode != "" {
		return fmt.Sprintf("Error code: %s", event.ErrorCode)
	}

	return ""
}

// HasErrorInformation checks if a CloudTrail event contains error information
func HasErrorInformation(event analyzer.CloudTrailEvent) bool {
	if event.ErrorCode != "" || event.ErrorMessage != "" {
		return true
	}

	if event.ResponseElements != nil {
		msg := ExtractMessageFromResponseElements(event.ResponseElements)
		return msg != ""
	}

	return false
}

// FilterErrorEvents filters CloudTrail events to only include those with error information
func FilterErrorEvents(events []analyzer.CloudTrailEvent) []analyzer.CloudTrailEvent {
	var errorEvents []analyzer.CloudTrailEvent
	for _, event := range events {
		if HasErrorInformation(event) {
			errorEvents = append(errorEvents, event)
		}
	}
	return errorEvents
}
