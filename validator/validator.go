// Package validator provides input validation for CloudFormation stack names
package validator

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"cfn-root-cause/awserrors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

var (
	// ErrEmptyStackName indicates an empty stack name was provided
	ErrEmptyStackName = errors.New("stack name cannot be empty")

	// ErrInvalidStackNameFormat indicates the stack name format is invalid
	ErrInvalidStackNameFormat = errors.New("invalid stack name format: must start with a letter, contain only alphanumeric characters and hyphens, and be 1-128 characters long")

	// ErrStackNotFound indicates the specified stack does not exist
	ErrStackNotFound = errors.New("stack not found")

	// ErrStackNameTooLong indicates the stack name exceeds maximum length
	ErrStackNameTooLong = errors.New("stack name exceeds maximum length of 128 characters")

	// ErrNoStacksFound indicates no CloudFormation stacks were found in the account
	ErrNoStacksFound = errors.New("no CloudFormation stacks found in your AWS account")
)

// stackNameRegex validates CloudFormation stack name format
// Stack names must:
// - Start with a letter
// - Contain only alphanumeric characters and hyphens
var stackNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)

// ValidateStackName validates the format of a CloudFormation stack name
// Returns nil if valid, or an error describing the validation failure
func ValidateStackName(name string) error {
	if name == "" {
		return ErrEmptyStackName
	}

	// Check length constraint (1-128 characters)
	if len(name) > 128 {
		return ErrStackNameTooLong
	}

	if !stackNameRegex.MatchString(name) {
		return ErrInvalidStackNameFormat
	}

	return nil
}

// CloudFormationClient defines the interface for CloudFormation operations needed by the validator
type CloudFormationClient interface {
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error)
}

// ValidateStackExists checks if a stack with the given name exists in CloudFormation
// Returns nil if the stack exists, or an error if it doesn't or if there's an API error
// Requirements: 6.4
func ValidateStackExists(ctx context.Context, client CloudFormationClient, stackName string) error {
	// First validate the format
	if err := ValidateStackName(stackName); err != nil {
		return err
	}

	// Check if stack exists via AWS API
	input := &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	}

	output, err := client.DescribeStacks(ctx, input)
	if err != nil {
		// Check if it's a "stack not found" error
		if isStackNotFoundError(err) {
			return fmt.Errorf("%w: stack '%s' does not exist in your AWS account", ErrStackNotFound, stackName)
		}
		// Parse and return user-friendly error message for other AWS errors
		awsErr := awserrors.ParseAWSError(err, "CloudFormation")
		return fmt.Errorf("failed to describe stack: %w", awsErr)
	}

	if len(output.Stacks) == 0 {
		return fmt.Errorf("%w: stack '%s' does not exist in your AWS account", ErrStackNotFound, stackName)
	}

	return nil
}

// isStackNotFoundError checks if the error indicates a stack was not found
func isStackNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// AWS SDK returns an error message containing "does not exist" for non-existent stacks
	errMsg := err.Error()
	return strings.Contains(errMsg, "does not exist") ||
		strings.Contains(errMsg, "Stack with id") ||
		strings.Contains(errMsg, "ValidationError")
}

// GetLatestStack finds the most recently updated CloudFormation stack
// It returns the stack name of the stack with the most recent LastUpdatedTime or CreationTime
// Requirements: 6.4
func GetLatestStack(ctx context.Context, client CloudFormationClient) (string, error) {
	// Define stack statuses to include - we want active stacks that could have errors
	statusFilters := []types.StackStatus{
		types.StackStatusCreateComplete,
		types.StackStatusCreateFailed,
		types.StackStatusCreateInProgress,
		types.StackStatusDeleteFailed,
		types.StackStatusDeleteInProgress,
		types.StackStatusRollbackComplete,
		types.StackStatusRollbackFailed,
		types.StackStatusRollbackInProgress,
		types.StackStatusUpdateComplete,
		types.StackStatusUpdateFailed,
		types.StackStatusUpdateInProgress,
		types.StackStatusUpdateRollbackComplete,
		types.StackStatusUpdateRollbackFailed,
		types.StackStatusUpdateRollbackInProgress,
	}

	var latestStackName string
	var latestTime time.Time
	var nextToken *string

	for {
		input := &cloudformation.ListStacksInput{
			StackStatusFilter: statusFilters,
			NextToken:         nextToken,
		}

		output, err := client.ListStacks(ctx, input)
		if err != nil {
			// Parse and return user-friendly error message for AWS errors
			awsErr := awserrors.ParseAWSError(err, "CloudFormation")
			return "", fmt.Errorf("failed to list CloudFormation stacks: %w", awsErr)
		}

		for _, summary := range output.StackSummaries {
			// Use LastUpdatedTime if available, otherwise use CreationTime
			var stackTime time.Time
			if summary.LastUpdatedTime != nil {
				stackTime = *summary.LastUpdatedTime
			} else if summary.CreationTime != nil {
				stackTime = *summary.CreationTime
			} else {
				continue
			}

			if stackTime.After(latestTime) {
				latestTime = stackTime
				if summary.StackName != nil {
					latestStackName = *summary.StackName
				}
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	if latestStackName == "" {
		return "", ErrNoStacksFound
	}

	return latestStackName, nil
}
