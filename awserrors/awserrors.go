// Package awserrors provides AWS authentication and permission error handling
// with meaningful error messages for common AWS SDK errors.
// Requirements: 6.2, 6.4
package awserrors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/smithy-go"
)

// Common AWS error types for easy checking
var (
	// ErrCredentialsNotFound indicates AWS credentials could not be resolved
	ErrCredentialsNotFound = errors.New("AWS credentials not found")

	// ErrCredentialsExpired indicates AWS credentials have expired
	ErrCredentialsExpired = errors.New("AWS credentials have expired")

	// ErrAccessDenied indicates the operation was denied due to insufficient permissions
	ErrAccessDenied = errors.New("access denied")

	// ErrInvalidCredentials indicates the provided credentials are invalid
	ErrInvalidCredentials = errors.New("invalid AWS credentials")

	// ErrRegionNotConfigured indicates no AWS region was configured
	ErrRegionNotConfigured = errors.New("AWS region not configured")

	// ErrServiceUnavailable indicates the AWS service is temporarily unavailable
	ErrServiceUnavailable = errors.New("AWS service temporarily unavailable")

	// ErrThrottling indicates the request was throttled due to rate limiting
	ErrThrottling = errors.New("request throttled")
)

// AWSError represents a parsed AWS error with user-friendly information
type AWSError struct {
	// OriginalError is the underlying AWS SDK error
	OriginalError error

	// ErrorType categorizes the error (credentials, permissions, service, etc.)
	ErrorType string

	// Message is a user-friendly error message
	Message string

	// Suggestion provides actionable guidance to resolve the error
	Suggestion string

	// AWSErrorCode is the AWS-specific error code if available
	AWSErrorCode string

	// Service is the AWS service that returned the error
	Service string
}

// Error implements the error interface
func (e *AWSError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s: %s\nSuggestion: %s", e.ErrorType, e.Message, e.Suggestion)
	}
	return fmt.Sprintf("%s: %s", e.ErrorType, e.Message)
}

// Unwrap returns the underlying error for errors.Is/As support
func (e *AWSError) Unwrap() error {
	return e.OriginalError
}

// ParseAWSError analyzes an AWS SDK error and returns a user-friendly AWSError.
// It handles credential resolution failures, permission issues, and other common errors.
// Requirements: 6.2, 6.4
func ParseAWSError(err error, service string) *AWSError {
	if err == nil {
		return nil
	}

	awsErr := &AWSError{
		OriginalError: err,
		Service:       service,
	}

	errMsg := err.Error()
	errMsgLower := strings.ToLower(errMsg)

	// Check for Smithy API errors (AWS SDK Go v2)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		awsErr.AWSErrorCode = apiErr.ErrorCode()
		return parseAPIError(awsErr, apiErr)
	}

	// Check for credential-related errors by message patterns
	if isCredentialError(errMsgLower) {
		return parseCredentialError(awsErr, errMsg)
	}

	// Check for region configuration errors
	if isRegionError(errMsgLower) {
		return parseRegionError(awsErr)
	}

	// Default: return generic error with original message
	awsErr.ErrorType = "AWS Error"
	awsErr.Message = errMsg
	awsErr.Suggestion = "Check AWS configuration and try again"

	return awsErr
}

// parseAPIError handles AWS API errors with specific error codes
func parseAPIError(awsErr *AWSError, apiErr smithy.APIError) *AWSError {
	code := apiErr.ErrorCode()
	message := apiErr.ErrorMessage()

	switch code {
	case "AccessDenied", "AccessDeniedException":
		awsErr.ErrorType = "Permission Error"
		awsErr.Message = fmt.Sprintf("Access denied: %s", message)
		awsErr.Suggestion = formatPermissionSuggestion(awsErr.Service)

	case "UnauthorizedAccess", "UnauthorizedOperation":
		awsErr.ErrorType = "Authorization Error"
		awsErr.Message = fmt.Sprintf("Unauthorized operation: %s", message)
		awsErr.Suggestion = formatPermissionSuggestion(awsErr.Service)

	case "ExpiredToken", "ExpiredTokenException":
		awsErr.ErrorType = "Credential Error"
		awsErr.Message = "AWS session token has expired"
		awsErr.Suggestion = "Refresh your AWS credentials. If using temporary credentials, obtain new ones. If using SSO, run 'aws sso login'."

	case "InvalidClientTokenId":
		awsErr.ErrorType = "Credential Error"
		awsErr.Message = "Invalid AWS access key ID"
		awsErr.Suggestion = "Verify your AWS access key ID is correct. Check your ~/.aws/credentials file or environment variables."

	case "SignatureDoesNotMatch":
		awsErr.ErrorType = "Credential Error"
		awsErr.Message = "AWS secret access key is incorrect"
		awsErr.Suggestion = "Verify your AWS secret access key is correct. Check your ~/.aws/credentials file or environment variables."

	case "ValidationError", "ValidationException":
		awsErr.ErrorType = "Validation Error"
		awsErr.Message = message
		awsErr.Suggestion = "Check the input parameters and try again"

	case "Throttling", "ThrottlingException", "RequestLimitExceeded":
		awsErr.ErrorType = "Rate Limit Error"
		awsErr.Message = "Request was throttled due to rate limiting"
		awsErr.Suggestion = "Wait a moment and try again. Consider implementing exponential backoff for repeated requests."

	case "ServiceUnavailable", "ServiceUnavailableException":
		awsErr.ErrorType = "Service Error"
		awsErr.Message = fmt.Sprintf("%s service is temporarily unavailable", awsErr.Service)
		awsErr.Suggestion = "Wait a moment and try again. Check AWS Service Health Dashboard for any ongoing issues."

	case "InternalError", "InternalFailure":
		awsErr.ErrorType = "Service Error"
		awsErr.Message = fmt.Sprintf("Internal error in %s service", awsErr.Service)
		awsErr.Suggestion = "This is an AWS-side issue. Wait a moment and try again."

	default:
		awsErr.ErrorType = "AWS API Error"
		awsErr.Message = fmt.Sprintf("[%s] %s", code, message)
		awsErr.Suggestion = "Check AWS documentation for this error code"
	}

	return awsErr
}

// isCredentialError checks if the error message indicates a credential issue
func isCredentialError(errMsgLower string) bool {
	credentialPatterns := []string{
		"no credentials",
		"credentials not found",
		"unable to locate credentials",
		"failed to retrieve credentials",
		"no valid credential",
		"credential provider",
		"no ec2 imds",
		"failed to load config",
		"no aws_access_key_id",
		"missing aws",
	}

	for _, pattern := range credentialPatterns {
		if strings.Contains(errMsgLower, pattern) {
			return true
		}
	}
	return false
}

// parseCredentialError creates an AWSError for credential-related issues
func parseCredentialError(awsErr *AWSError, errMsg string) *AWSError {
	awsErr.ErrorType = "Credential Error"
	awsErr.Message = "AWS credentials could not be found or loaded"
	awsErr.Suggestion = `AWS credentials are not configured. Please configure credentials using one of these methods:
  1. Set environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
  2. Configure AWS CLI: run 'aws configure'
  3. Use AWS SSO: run 'aws sso login --profile <profile-name>'
  4. Use IAM role (for EC2/ECS/Lambda)
  
For more information, see: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html`

	return awsErr
}

// isRegionError checks if the error message indicates a region configuration issue
func isRegionError(errMsgLower string) bool {
	regionPatterns := []string{
		"no region",
		"region not found",
		"missing region",
		"could not find region",
	}

	for _, pattern := range regionPatterns {
		if strings.Contains(errMsgLower, pattern) {
			return true
		}
	}
	return false
}

// parseRegionError creates an AWSError for region configuration issues
func parseRegionError(awsErr *AWSError) *AWSError {
	awsErr.ErrorType = "Configuration Error"
	awsErr.Message = "AWS region is not configured"
	awsErr.Suggestion = `AWS region is not set. Please configure a region using one of these methods:
  1. Set environment variable: AWS_REGION or AWS_DEFAULT_REGION
  2. Configure in ~/.aws/config: add 'region = us-east-1' under [default]
  3. Use AWS CLI: run 'aws configure' and specify a region`

	return awsErr
}

// formatPermissionSuggestion returns a service-specific permission suggestion
func formatPermissionSuggestion(service string) string {
	base := "Ensure your AWS credentials have the required permissions."

	switch service {
	case "CloudFormation":
		return base + `
Required permissions for CloudFormation analysis:
  - cloudformation:DescribeStacks
  - cloudformation:DescribeStackEvents
  - cloudformation:ListStacks`

	case "CloudTrail":
		return base + `
Required permissions for CloudTrail analysis:
  - cloudtrail:LookupEvents`

	default:
		return base + "\nCheck the IAM policy attached to your user/role."
	}
}

// IsCredentialError checks if the error is related to AWS credentials
func IsCredentialError(err error) bool {
	if err == nil {
		return false
	}

	var awsErr *AWSError
	if errors.As(err, &awsErr) {
		return awsErr.ErrorType == "Credential Error"
	}

	errMsgLower := strings.ToLower(err.Error())
	return isCredentialError(errMsgLower)
}

// IsPermissionError checks if the error is related to AWS permissions
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}

	var awsErr *AWSError
	if errors.As(err, &awsErr) {
		return awsErr.ErrorType == "Permission Error" || awsErr.ErrorType == "Authorization Error"
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "AccessDenied" || code == "AccessDeniedException" ||
			code == "UnauthorizedAccess" || code == "UnauthorizedOperation"
	}

	return false
}

// IsThrottlingError checks if the error is due to rate limiting
func IsThrottlingError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "Throttling" || code == "ThrottlingException" ||
			code == "RequestLimitExceeded" || code == "TooManyRequestsException"
	}

	return false
}

// IsRetryableError checks if the error is transient and can be retried
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Throttling errors are retryable
	if IsThrottlingError(err) {
		return true
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		retryableCodes := []string{
			"ServiceUnavailable",
			"ServiceUnavailableException",
			"InternalError",
			"InternalFailure",
			"RequestTimeout",
			"RequestTimeoutException",
		}
		for _, retryable := range retryableCodes {
			if code == retryable {
				return true
			}
		}
	}

	return false
}

// FormatErrorForUser formats an AWS error for display to the user
func FormatErrorForUser(err error, service string) string {
	awsErr := ParseAWSError(err, service)
	return awsErr.Error()
}
