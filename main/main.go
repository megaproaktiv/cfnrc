package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"cfn-root-cause/analyzer"
	"cfn-root-cause/cfnclient"
	"cfn-root-cause/cloudtrail"
	"cfn-root-cause/correlator"
	"cfn-root-cause/extractor"
	"cfn-root-cause/formatter"
	"cfn-root-cause/validator"
)

func main() {
	ctx := context.Background()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run executes the main analysis workflow
func run(ctx context.Context) error {
	// Parse command line arguments
	stackName, err := parseArgs()
	if err != nil {
		return err
	}

	fmt.Println("CloudFormation Error Analyzer")
	fmt.Println()

	// Initialize CloudFormation client
	cfnClient, err := cfnclient.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize CloudFormation client: %w", err)
	}

	// Determine which stack to analyze
	stackName, err = resolveStackName(ctx, cfnClient, stackName)
	if err != nil {
		return err
	}

	fmt.Printf("Analyzing stack: %s\n", stackName)
	fmt.Println()

	// Validate the stack exists
	if err := validator.ValidateStackExists(ctx, cfnClient, stackName); err != nil {
		return err
	}

	// Perform the analysis
	analysis, err := analyzeStack(ctx, cfnClient, stackName)
	if err != nil {
		return err
	}

	// Format and display results
	output := formatter.FormatAnalysisResults(analysis)
	fmt.Print(output)

	return nil
}

// resolveStackName determines the stack name to analyze.
// If a stack name is provided, it returns that name.
// Otherwise, it finds the most recently updated stack.
func resolveStackName(ctx context.Context, cfnClient *cfnclient.Client, providedName string) (string, error) {
	if providedName != "" {
		return providedName, nil
	}

	fmt.Println("No stack name provided, finding most recently updated stack...")

	stackName, err := validator.GetLatestStack(ctx, cfnClient)
	if err != nil {
		return "", fmt.Errorf("failed to find latest stack: %w", err)
	}

	return stackName, nil
}

// analyzeStack performs the complete analysis workflow for a CloudFormation stack.
// It retrieves stack events, extracts errors, queries CloudTrail for GeneralServiceExceptions,
// and correlates the results.
func analyzeStack(ctx context.Context, cfnClient *cfnclient.Client, stackName string) (*analyzer.StackAnalysis, error) {
	// Get stack events
	fmt.Println("Retrieving stack events...")
	events, err := cfnClient.GetStackEvents(ctx, stackName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve stack events: %w", err)
	}

	// Extract errors from events
	stackErrors := extractor.ExtractErrors(events)
	
	// Filter to only include errors from today
	stackErrors = filterErrorsByDate(stackErrors, time.Now())

	if len(stackErrors) == 0 {
		return &analyzer.StackAnalysis{
			StackName:    stackName,
			AnalysisTime: time.Now(),
			Errors:       []analyzer.CorrelatedError{},
		}, nil
	}

	fmt.Printf("Found %d error(s) in stack events\n", len(stackErrors))

	// Count GeneralServiceExceptions
	generalServiceExceptions := 0
	for _, err := range stackErrors {
		if err.IsGeneralServiceException {
			generalServiceExceptions++
		}
	}

	// Query CloudTrail for GeneralServiceException errors
	var trailEvents []analyzer.CloudTrailEvent
	if generalServiceExceptions > 0 {
		fmt.Printf("Found %d GeneralServiceException(s), querying CloudTrail for details...\n", generalServiceExceptions)

		trailEvents, err = queryCloudTrailForErrors(ctx, stackErrors)
		if err != nil {
			// Log warning but continue - CloudTrail data is supplementary
			fmt.Fprintf(os.Stderr, "Warning: Failed to query CloudTrail: %v\n", err)
		}
	}

	// Correlate CloudFormation errors with CloudTrail events
	correlatedErrors := correlator.CorrelateErrors(stackErrors, trailEvents)

	// Count errors with CloudTrail details
	detailedErrors := 0
	for _, err := range correlatedErrors {
		if err.CloudTrailEvent != nil {
			detailedErrors++
		}
	}

	return &analyzer.StackAnalysis{
		StackName:      stackName,
		AnalysisTime:   time.Now(),
		Errors:         correlatedErrors,
		GeneralErrors:  generalServiceExceptions,
		DetailedErrors: detailedErrors,
	}, nil
}

// queryCloudTrailForErrors queries CloudTrail for events related to stack errors.
// It focuses on GeneralServiceException errors that need CloudTrail investigation.
func queryCloudTrailForErrors(ctx context.Context, stackErrors []analyzer.StackError) ([]analyzer.CloudTrailEvent, error) {
	// Initialize CloudTrail client
	ctClient, err := cloudtrail.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CloudTrail client: %w", err)
	}

	var allTrailEvents []analyzer.CloudTrailEvent

	// Query CloudTrail for each GeneralServiceException error
	for _, stackErr := range stackErrors {
		if !stackErr.IsGeneralServiceException {
			continue
		}

		events, err := ctClient.SearchForStackErrors(ctx, stackErr)
		if err != nil {
			// Log warning but continue with other errors
			fmt.Fprintf(os.Stderr, "Warning: Failed to query CloudTrail for resource %s: %v\n",
				stackErr.LogicalResourceId, err)
			continue
		}

		// Filter to only include events with error information
		errorEvents := cloudtrail.FilterErrorEvents(events)
		allTrailEvents = append(allTrailEvents, errorEvents...)
	}

	return allTrailEvents, nil
}

// parseArgs parses command line arguments and returns the stack name.
// Returns empty string if no stack name provided (indicating default behavior).
func parseArgs() (string, error) {
	args := os.Args[1:] // Skip program name

	if len(args) == 0 {
		// No arguments provided - use default behavior (most recent stack)
		return "", nil
	}

	if len(args) == 1 {
		stackName := args[0]

		// Validate stack name format before processing
		if err := validator.ValidateStackName(stackName); err != nil {
			return "", err
		}

		return stackName, nil
	}

	// Too many arguments
	return "", fmt.Errorf("usage: %s [stack-name]", os.Args[0])
}

// filterErrorsByDate filters stack errors to only include those from the same day as the reference date
func filterErrorsByDate(errors []analyzer.StackError, referenceDate time.Time) []analyzer.StackError {
	// Get the start and end of the reference day (in UTC)
	year, month, day := referenceDate.UTC().Date()
	startOfDay := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)
	
	var filtered []analyzer.StackError
	for _, err := range errors {
		// Check if error timestamp is within the same day
		if err.Timestamp.After(startOfDay) && err.Timestamp.Before(endOfDay) {
			filtered = append(filtered, err)
		}
	}
	
	return filtered
}
