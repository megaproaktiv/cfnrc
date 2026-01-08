// Package cfnclient provides CloudFormation client initialization and operations
package cfnclient

import (
	"context"
	"fmt"

	"cfn-root-cause/awserrors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// Client wraps the AWS CloudFormation client with additional functionality
type Client struct {
	cfn *cloudformation.Client
}

// CloudFormationAPI defines the interface for CloudFormation operations
type CloudFormationAPI interface {
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	DescribeStackEvents(ctx context.Context, params *cloudformation.DescribeStackEventsInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStackEventsOutput, error)
	ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error)
}

// NewClient creates a new CloudFormation client using default AWS configuration
// It uses standard AWS credential resolution (environment variables, profiles, IAM roles)
// Requirements: 6.2, 6.4
func NewClient(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		// Parse and return user-friendly error message for credential/config issues
		awsErr := awserrors.ParseAWSError(err, "CloudFormation")
		return nil, awsErr
	}

	return &Client{
		cfn: cloudformation.NewFromConfig(cfg),
	}, nil
}

// NewClientWithConfig creates a new CloudFormation client with a custom AWS config
func NewClientWithConfig(cfg aws.Config) *Client {
	return &Client{
		cfn: cloudformation.NewFromConfig(cfg),
	}
}

// GetStackEvents retrieves all stack events for the specified stack name
// It handles pagination to retrieve all events
// Requirements: 6.4
func (c *Client) GetStackEvents(ctx context.Context, stackName string) ([]types.StackEvent, error) {
	var allEvents []types.StackEvent
	var nextToken *string

	for {
		input := &cloudformation.DescribeStackEventsInput{
			StackName: aws.String(stackName),
			NextToken: nextToken,
		}

		output, err := c.cfn.DescribeStackEvents(ctx, input)
		if err != nil {
			// Parse and return user-friendly error message
			awsErr := awserrors.ParseAWSError(err, "CloudFormation")
			return nil, fmt.Errorf("failed to describe stack events for '%s': %w", stackName, awsErr)
		}

		allEvents = append(allEvents, output.StackEvents...)

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allEvents, nil
}

// DescribeStacks retrieves stack information for the specified stack name
func (c *Client) DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	return c.cfn.DescribeStacks(ctx, params, optFns...)
}

// ListStacks lists all stacks with the specified status filters
func (c *Client) ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error) {
	return c.cfn.ListStacks(ctx, params, optFns...)
}

// GetUnderlyingClient returns the underlying AWS CloudFormation client
// This is useful when direct access to the AWS SDK client is needed
func (c *Client) GetUnderlyingClient() *cloudformation.Client {
	return c.cfn
}
