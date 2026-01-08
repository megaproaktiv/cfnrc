// Package formatter provides output formatting and display functionality
package formatter

import (
	"fmt"
	"strings"
	"time"

	"cfn-root-cause/analyzer"
)

const (
	// ANSI color codes for terminal output
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"

	// Formatting constants
	separator      = "─"
	separatorWidth = 80
	indentWidth    = 2
)

// FormatAnalysisResults formats the complete analysis results for display.
// It combines CloudFormation errors with CloudTrail details in a unified report.
// Requirements: 5.1, 5.2, 5.4
func FormatAnalysisResults(analysis *analyzer.StackAnalysis) string {
	if analysis == nil {
		return "No analysis results available."
	}

	var sb strings.Builder

	// Header section
	sb.WriteString(formatHeader(analysis))

	// Summary section
	sb.WriteString(formatSummary(analysis))

	// Errors section
	if len(analysis.Errors) == 0 {
		sb.WriteString("\nNo errors found in stack events.\n")
	} else {
		sb.WriteString(formatErrorsSection(analysis.Errors))
	}

	return sb.String()
}

// FormatError formats an individual correlated error for display.
// It shows CloudFormation error info with timestamps and resource details,
// and includes CloudTrail details when available.
// Requirements: 2.4, 5.1, 5.2
func FormatError(err analyzer.CorrelatedError) string {
	var sb strings.Builder

	// CloudFormation error details
	sb.WriteString(formatStackError(err.StackError))

	// CloudTrail details if available
	if err.CloudTrailEvent != nil {
		sb.WriteString(formatCloudTrailDetails(err.CloudTrailEvent))
	}

	// Detailed message (from CloudTrail or original)
	if err.DetailedMessage != "" {
		sb.WriteString(formatDetailedMessage(err.DetailedMessage, err.CloudTrailEvent != nil))
	}

	return sb.String()
}

// formatHeader creates the report header with stack name and analysis time
func formatHeader(analysis *analyzer.StackAnalysis) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(strings.Repeat(separator, separatorWidth))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%sCloudFormation Error Analysis Report%s\n", colorBold, colorReset))
	sb.WriteString(strings.Repeat(separator, separatorWidth))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Stack Name:    %s%s%s\n", colorCyan, analysis.StackName, colorReset))
	sb.WriteString(fmt.Sprintf("Analysis Time: %s\n", formatTimestamp(analysis.AnalysisTime)))

	return sb.String()
}

// formatSummary creates the summary section with error counts
func formatSummary(analysis *analyzer.StackAnalysis) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%sSummary%s\n", colorBold, colorReset))
	sb.WriteString(strings.Repeat(separator, 40))
	sb.WriteString("\n")

	totalErrors := len(analysis.Errors)
	sb.WriteString(fmt.Sprintf("Total Errors:              %d\n", totalErrors))
	sb.WriteString(fmt.Sprintf("GeneralServiceExceptions:  %d\n", analysis.GeneralErrors))
	sb.WriteString(fmt.Sprintf("With CloudTrail Details:   %d\n", analysis.DetailedErrors))

	return sb.String()
}

// formatErrorsSection formats all errors in the analysis
func formatErrorsSection(errors []analyzer.CorrelatedError) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%sErrors%s\n", colorBold, colorReset))
	sb.WriteString(strings.Repeat(separator, separatorWidth))
	sb.WriteString("\n")

	for i, err := range errors {
		sb.WriteString(fmt.Sprintf("\n%s[Error %d]%s\n", colorRed, i+1, colorReset))
		sb.WriteString(FormatError(err))
	}

	return sb.String()
}

// formatStackError formats the CloudFormation stack error details
// Requirements: 2.4, 5.1
func formatStackError(err analyzer.StackError) string {
	var sb strings.Builder

	indent := strings.Repeat(" ", indentWidth)

	sb.WriteString(fmt.Sprintf("%sTimestamp:     %s\n", indent, formatTimestamp(err.Timestamp)))
	sb.WriteString(fmt.Sprintf("%sResource:      %s%s%s\n", indent, colorCyan, err.LogicalResourceId, colorReset))
	sb.WriteString(fmt.Sprintf("%sResource Type: %s\n", indent, err.ResourceType))
	sb.WriteString(fmt.Sprintf("%sStatus:        %s%s%s\n", indent, colorRed, err.ResourceStatus, colorReset))

	if err.ResourceStatusReason != "" {
		sb.WriteString(fmt.Sprintf("%sReason:        %s\n", indent, err.ResourceStatusReason))
	}

	if err.IsGeneralServiceException {
		sb.WriteString(fmt.Sprintf("%s%s⚠ GeneralServiceException - CloudTrail investigation required%s\n",
			indent, colorYellow, colorReset))
	}

	return sb.String()
}

// formatCloudTrailDetails formats the CloudTrail event details
// Requirements: 5.2
func formatCloudTrailDetails(event *analyzer.CloudTrailEvent) string {
	var sb strings.Builder

	indent := strings.Repeat(" ", indentWidth)

	sb.WriteString(fmt.Sprintf("\n%s%sCloudTrail Details:%s\n", indent, colorBold, colorReset))

	innerIndent := strings.Repeat(" ", indentWidth*2)

	sb.WriteString(fmt.Sprintf("%sEvent Time:   %s\n", innerIndent, formatTimestamp(event.EventTime)))
	sb.WriteString(fmt.Sprintf("%sEvent Name:   %s\n", innerIndent, event.EventName))
	sb.WriteString(fmt.Sprintf("%sEvent Source: %s\n", innerIndent, event.EventSource))

	if event.ErrorCode != "" {
		sb.WriteString(fmt.Sprintf("%sError Code:   %s%s%s\n", innerIndent, colorRed, event.ErrorCode, colorReset))
	}

	if event.ErrorMessage != "" {
		sb.WriteString(fmt.Sprintf("%sError Msg:    %s\n", innerIndent, event.ErrorMessage))
	}

	return sb.String()
}

// formatDetailedMessage formats the detailed error message
func formatDetailedMessage(message string, hasCloudTrail bool) string {
	var sb strings.Builder

	indent := strings.Repeat(" ", indentWidth)

	sb.WriteString("\n")
	if hasCloudTrail {
		sb.WriteString(fmt.Sprintf("%s%sDetailed Message (from CloudTrail):%s\n", indent, colorBold, colorReset))
	} else {
		sb.WriteString(fmt.Sprintf("%s%sDetailed Message:%s\n", indent, colorBold, colorReset))
	}

	innerIndent := strings.Repeat(" ", indentWidth*2)
	sb.WriteString(fmt.Sprintf("%s%s\n", innerIndent, message))

	return sb.String()
}

// formatTimestamp formats a time.Time for display
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

// FormatPlainText formats analysis results without ANSI color codes
// Useful for file output or non-terminal environments
func FormatPlainText(analysis *analyzer.StackAnalysis) string {
	if analysis == nil {
		return "No analysis results available."
	}

	var sb strings.Builder

	// Header
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("=", separatorWidth))
	sb.WriteString("\n")
	sb.WriteString("CloudFormation Error Analysis Report\n")
	sb.WriteString(strings.Repeat("=", separatorWidth))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("Stack Name:    %s\n", analysis.StackName))
	sb.WriteString(fmt.Sprintf("Analysis Time: %s\n", formatTimestamp(analysis.AnalysisTime)))

	// Summary
	sb.WriteString("\nSummary\n")
	sb.WriteString(strings.Repeat("-", 40))
	sb.WriteString("\n")

	totalErrors := len(analysis.Errors)
	sb.WriteString(fmt.Sprintf("Total Errors:              %d\n", totalErrors))
	sb.WriteString(fmt.Sprintf("GeneralServiceExceptions:  %d\n", analysis.GeneralErrors))
	sb.WriteString(fmt.Sprintf("With CloudTrail Details:   %d\n", analysis.DetailedErrors))

	// Errors
	if len(analysis.Errors) == 0 {
		sb.WriteString("\nNo errors found in stack events.\n")
	} else {
		sb.WriteString("\nErrors\n")
		sb.WriteString(strings.Repeat("=", separatorWidth))
		sb.WriteString("\n")

		for i, err := range analysis.Errors {
			sb.WriteString(fmt.Sprintf("\n[Error %d]\n", i+1))
			sb.WriteString(FormatErrorPlainText(err))
		}
	}

	return sb.String()
}

// FormatErrorPlainText formats an individual error without ANSI color codes
func FormatErrorPlainText(err analyzer.CorrelatedError) string {
	var sb strings.Builder

	indent := strings.Repeat(" ", indentWidth)

	// CloudFormation error details
	sb.WriteString(fmt.Sprintf("%sTimestamp:     %s\n", indent, formatTimestamp(err.StackError.Timestamp)))
	sb.WriteString(fmt.Sprintf("%sResource:      %s\n", indent, err.StackError.LogicalResourceId))
	sb.WriteString(fmt.Sprintf("%sResource Type: %s\n", indent, err.StackError.ResourceType))
	sb.WriteString(fmt.Sprintf("%sStatus:        %s\n", indent, err.StackError.ResourceStatus))

	if err.StackError.ResourceStatusReason != "" {
		sb.WriteString(fmt.Sprintf("%sReason:        %s\n", indent, err.StackError.ResourceStatusReason))
	}

	if err.StackError.IsGeneralServiceException {
		sb.WriteString(fmt.Sprintf("%s[!] GeneralServiceException - CloudTrail investigation required\n", indent))
	}

	// CloudTrail details if available
	if err.CloudTrailEvent != nil {
		sb.WriteString(fmt.Sprintf("\n%sCloudTrail Details:\n", indent))

		innerIndent := strings.Repeat(" ", indentWidth*2)
		sb.WriteString(fmt.Sprintf("%sEvent Time:   %s\n", innerIndent, formatTimestamp(err.CloudTrailEvent.EventTime)))
		sb.WriteString(fmt.Sprintf("%sEvent Name:   %s\n", innerIndent, err.CloudTrailEvent.EventName))
		sb.WriteString(fmt.Sprintf("%sEvent Source: %s\n", innerIndent, err.CloudTrailEvent.EventSource))

		if err.CloudTrailEvent.ErrorCode != "" {
			sb.WriteString(fmt.Sprintf("%sError Code:   %s\n", innerIndent, err.CloudTrailEvent.ErrorCode))
		}

		if err.CloudTrailEvent.ErrorMessage != "" {
			sb.WriteString(fmt.Sprintf("%sError Msg:    %s\n", innerIndent, err.CloudTrailEvent.ErrorMessage))
		}
	}

	// Detailed message
	if err.DetailedMessage != "" {
		sb.WriteString("\n")
		if err.CloudTrailEvent != nil {
			sb.WriteString(fmt.Sprintf("%sDetailed Message (from CloudTrail):\n", indent))
		} else {
			sb.WriteString(fmt.Sprintf("%sDetailed Message:\n", indent))
		}
		innerIndent := strings.Repeat(" ", indentWidth*2)
		sb.WriteString(fmt.Sprintf("%s%s\n", innerIndent, err.DetailedMessage))
	}

	return sb.String()
}

// FormatCompact formats analysis results in a compact single-line-per-error format
// Useful for quick scanning or piping to other tools
func FormatCompact(analysis *analyzer.StackAnalysis) string {
	if analysis == nil {
		return "No analysis results available."
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Stack: %s | Errors: %d | GeneralServiceExceptions: %d | With CloudTrail: %d\n",
		analysis.StackName, len(analysis.Errors), analysis.GeneralErrors, analysis.DetailedErrors))

	for _, err := range analysis.Errors {
		sb.WriteString(FormatErrorCompact(err))
	}

	return sb.String()
}

// FormatErrorCompact formats an individual error in compact format
func FormatErrorCompact(err analyzer.CorrelatedError) string {
	timestamp := formatTimestamp(err.StackError.Timestamp)
	resource := err.StackError.LogicalResourceId
	status := err.StackError.ResourceStatus

	var detail string
	if err.DetailedMessage != "" {
		// Truncate long messages for compact format
		detail = err.DetailedMessage
		if len(detail) > 100 {
			detail = detail[:97] + "..."
		}
	}

	gseFlag := ""
	if err.StackError.IsGeneralServiceException {
		gseFlag = " [GSE]"
	}

	ctFlag := ""
	if err.CloudTrailEvent != nil {
		ctFlag = " [CT]"
	}

	return fmt.Sprintf("%s | %s | %s%s%s | %s\n", timestamp, resource, status, gseFlag, ctFlag, detail)
}
