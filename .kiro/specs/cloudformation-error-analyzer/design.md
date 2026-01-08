# Design Document: CloudFormation Error Analyzer

## Overview

The CloudFormation Error Analyzer is a Go CLI application that helps developers diagnose CloudFormation stack creation failures by correlating stack events with detailed CloudTrail logs. When CloudFormation returns generic errors like "GeneralServiceException", the tool automatically searches CloudTrail for the underlying API call failures and extracts detailed error messages from the responseElements field.

By default, the analyzer focuses on recent errors (within the last 1 hour) to provide quick diagnostics. For comprehensive historical analysis, users can use the `--full` flag to analyze all available errors.

## Architecture

The application follows a modular architecture with clear separation of concerns:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Handler   │───▶│  Stack Analyzer  │───▶│ CloudTrail API  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Input Validator │    │CloudFormation API│    │ Error Correlator│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │  Error Extractor │    │ Output Formatter│
                       └──────────────────┘    └─────────────────┘
```

## Components and Interfaces

### CLI Handler
- **Purpose**: Parse command line arguments and orchestrate the analysis workflow
- **Interface**: 
  - `func main()` - Entry point
  - `func parseArgs() (stackName string, fullHistory bool, err error)` - Parse CLI arguments including --full flag
- **Dependencies**: Input Validator, Stack Analyzer
- **Behavior**: By default, only analyzes errors from the last 1 hour. When --full flag is provided, analyzes all available errors.

### Input Validator
- **Purpose**: Validate stack names and handle default stack selection
- **Interface**:
  - `func ValidateStackName(name string) error` - Validate stack name format
  - `func GetLatestStack(ctx context.Context, cfnClient *cloudformation.Client) (string, error)` - Find most recent stack
- **Dependencies**: CloudFormation API

### Stack Analyzer
- **Purpose**: Retrieve and analyze CloudFormation stack events
- **Interface**:
  - `func AnalyzeStackErrors(ctx context.Context, stackName string, timeFilter TimeFilter) (*StackAnalysis, error)` - Main analysis function with time filtering
  - `func GetStackEvents(ctx context.Context, stackName string) ([]types.StackEvent, error)` - Retrieve stack events
  - `func FilterEventsByTime(events []types.StackEvent, timeFilter TimeFilter) []types.StackEvent` - Filter events by time range
- **Dependencies**: CloudFormation API, Error Extractor

### Error Extractor
- **Purpose**: Extract and categorize errors from stack events
- **Interface**:
  - `func ExtractErrors(events []types.StackEvent) []StackError` - Extract errors from events
  - `func IsGeneralServiceException(err StackError) bool` - Identify generic errors needing CloudTrail lookup
- **Dependencies**: None

### CloudTrail API
- **Purpose**: Query CloudTrail logs for detailed error information
- **Interface**:
  - `func SearchCloudTrailEvents(ctx context.Context, timeRange TimeRange, filters []string) ([]CloudTrailEvent, error)` - Search logs within specified time range
  - `func ExtractResponseElements(event CloudTrailEvent) (map[string]interface{}, error)` - Parse response elements
- **Dependencies**: AWS SDK CloudTrail client
- **Behavior**: Time range is determined by the --full flag. Default searches last 1 hour, --full searches all available history.

### Error Correlator
- **Purpose**: Match CloudFormation errors with CloudTrail events
- **Interface**:
  - `func CorrelateErrors(cfnErrors []StackError, trailEvents []CloudTrailEvent) []CorrelatedError` - Match errors
  - `func FindMatchingTrailEvent(cfnError StackError, trailEvents []CloudTrailEvent) *CloudTrailEvent` - Find specific matches
- **Dependencies**: None

### Output Formatter
- **Purpose**: Format and display analysis results
- **Interface**:
  - `func FormatAnalysisResults(analysis *StackAnalysis) string` - Format complete results
  - `func FormatError(err CorrelatedError) string` - Format individual errors
- **Dependencies**: None

## Data Models

### StackError
```go
type StackError struct {
    Timestamp         time.Time
    ResourceType      string
    LogicalResourceId string
    ResourceStatus    string
    ResourceStatusReason string
    EventId          string
    IsGeneralServiceException bool
}
```

### CloudTrailEvent
```go
type CloudTrailEvent struct {
    EventTime        time.Time
    EventName        string
    EventSource      string
    UserIdentity     map[string]interface{}
    ResponseElements map[string]interface{}
    ErrorCode        string
    ErrorMessage     string
}
```

### CorrelatedError
```go
type CorrelatedError struct {
    StackError      StackError
    CloudTrailEvent *CloudTrailEvent
    DetailedMessage string
}
```

### StackAnalysis
```go
type StackAnalysis struct {
    StackName        string
    AnalysisTime     time.Time
    Errors          []CorrelatedError
    GeneralErrors   int
    DetailedErrors  int
}
```

### TimeRange
```go
type TimeRange struct {
    StartTime time.Time
    EndTime   time.Time
}
```

### TimeFilter
```go
type TimeFilter struct {
    FullHistory bool
    MaxAge      time.Duration // Default: 1 hour
}

func (tf TimeFilter) GetTimeRange() TimeRange {
    endTime := time.Now()
    var startTime time.Time
    if tf.FullHistory {
        startTime = time.Time{} // Zero time for all history
    } else {
        startTime = endTime.Add(-tf.MaxAge)
    }
    return TimeRange{StartTime: startTime, EndTime: endTime}
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Stack Name Input Validation
*For any* valid stack name provided as input, the analyzer should use exactly that stack name for analysis and validate the format before processing
**Validates: Requirements 1.1, 1.4**

### Property 2: Default Stack Selection
*For any* CloudFormation environment with multiple stacks, when no stack name is provided, the analyzer should automatically select the most recently updated stack
**Validates: Requirements 1.2**

### Property 3: Invalid Stack Error Handling
*For any* non-existent or invalid stack name, the analyzer should return a descriptive error message without attempting analysis
**Validates: Requirements 1.3**

### Property 4: Error Event Detection
*For any* set of CloudFormation stack events containing errors, the analyzer should identify and extract all error events without missing any
**Validates: Requirements 2.2**

### Property 5: GeneralServiceException Flagging
*For any* stack events containing GeneralServiceException errors, the analyzer should flag them for CloudTrail investigation
**Validates: Requirements 2.3**

### Property 6: CloudTrail Query Correlation
*For any* GeneralServiceException detected in CloudFormation, the analyzer should query CloudTrail logs for the corresponding time period and related API calls
**Validates: Requirements 3.1, 3.2**

### Property 7: ResponseElements Extraction
*For any* CloudTrail event containing responseElements data, the analyzer should correctly extract and parse the responseElements including any message fields
**Validates: Requirements 3.3, 4.1**

### Property 8: Event Correlation
*For any* CloudFormation error and corresponding CloudTrail events, the analyzer should correctly correlate them by timestamp and resource identifiers
**Validates: Requirements 3.4**

### Property 9: Message Field Handling
*For any* CloudTrail responseElements, the analyzer should display detailed error messages when present and handle missing message fields gracefully
**Validates: Requirements 4.2, 4.3**

### Property 10: Context Preservation
*For any* error processing, the analyzer should preserve original error context including timestamps and API call details throughout the analysis
**Validates: Requirements 4.4**

### Property 11: Comprehensive Error Display
*For any* analysis results, the output should include both CloudFormation stack errors with timestamps/resource information and corresponding CloudTrail error details when available
**Validates: Requirements 5.1, 5.2, 5.4**

### Property 12: AWS Authentication Error Handling
*For any* AWS authentication or permission failures, the analyzer should provide meaningful error messages that help diagnose the issue
**Validates: Requirements 6.4**

### Property 13: Default Time Filtering
*For any* analysis execution without the --full flag, the analyzer should only process and display errors that occurred within the last 1 hour from the current time
**Validates: Requirements 7.1, 7.3**

### Property 14: Full History Mode
*For any* analysis execution with the --full flag, the analyzer should process and display all available errors regardless of their age
**Validates: Requirements 7.2, 7.3**

## Error Handling

The application implements comprehensive error handling at multiple levels:

### Input Validation Errors
- Invalid stack name formats
- Non-existent stack names
- Missing AWS credentials

### AWS API Errors
- CloudFormation API failures (permissions, rate limits, service unavailability)
- CloudTrail API failures (permissions, log retention issues)
- Network connectivity issues

### Data Processing Errors
- Malformed CloudTrail log entries
- Missing or corrupted responseElements
- Timestamp parsing failures

### Error Recovery Strategies
- Graceful degradation when CloudTrail data is unavailable
- Retry logic for transient AWS API failures
- Clear error messages with actionable guidance

## Testing Strategy

The CloudFormation Error Analyzer will use a dual testing approach combining unit tests and property-based tests to ensure comprehensive coverage and correctness.

### Unit Testing
Unit tests will focus on:
- Specific examples of CloudFormation error scenarios
- Edge cases like empty stack events or malformed CloudTrail logs
- Integration points between AWS services
- Error conditions and boundary values

### Property-Based Testing
Property-based tests will verify universal properties across all inputs using a Go property testing library such as `gopter` or `rapid`. Each test will run a minimum of 100 iterations to ensure comprehensive input coverage.

Property tests will focus on:
- Input validation across all possible stack name formats
- Error detection across randomly generated stack events
- Data correlation between CloudFormation and CloudTrail events
- Output formatting consistency across various error scenarios

### Test Configuration
- Minimum 100 iterations per property test
- Each property test references its design document property
- Tag format: **Feature: cloudformation-error-analyzer, Property {number}: {property_text}**
- Mock AWS services for consistent testing without external dependencies
- Integration tests with real AWS services in separate test suite