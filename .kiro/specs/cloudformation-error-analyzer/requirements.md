# Requirements Document

## Introduction

A Go program that analyzes CloudFormation stack creation errors by examining CloudTrail logs to extract detailed error messages, particularly for GeneralServiceException errors that require deeper investigation.

## Glossary

- **CloudFormation_Stack**: An AWS CloudFormation stack resource collection
- **CloudTrail_Log**: AWS service that records API calls and events
- **Error_Analyzer**: The Go program that processes CloudFormation and CloudTrail data
- **GeneralServiceException**: A generic AWS error that requires CloudTrail investigation
- **ResponseElements**: The detailed error information contained in CloudTrail logs

## Requirements

### Requirement 1: Stack Input Handling

**User Story:** As a developer, I want to specify a CloudFormation stack name or use the latest updated stack, so that I can analyze errors for the correct stack.

#### Acceptance Criteria

1. WHEN a stack name is provided as a command line argument, THE Error_Analyzer SHALL use that specific stack for analysis
2. WHEN no stack name is provided, THE Error_Analyzer SHALL automatically identify and use the most recently updated CloudFormation stack
3. WHEN the specified stack does not exist, THE Error_Analyzer SHALL return a descriptive error message
4. THE Error_Analyzer SHALL validate stack name format before processing

### Requirement 2: CloudFormation Error Detection

**User Story:** As a developer, I want to identify CloudFormation stack creation errors, so that I can understand what went wrong during deployment.

#### Acceptance Criteria

1. THE Error_Analyzer SHALL retrieve CloudFormation stack events using AWS SDK Go v2
2. WHEN stack events contain errors, THE Error_Analyzer SHALL identify and extract all error events
3. WHEN a GeneralServiceException is found, THE Error_Analyzer SHALL flag it for CloudTrail investigation
4. THE Error_Analyzer SHALL display basic error information from CloudFormation events

### Requirement 3: CloudTrail Log Analysis

**User Story:** As a developer, I want to examine CloudTrail logs for detailed error information, so that I can understand the root cause of GeneralServiceException errors.

#### Acceptance Criteria

1. WHEN a GeneralServiceException is detected, THE Error_Analyzer SHALL query CloudTrail logs for the corresponding time period
2. THE Error_Analyzer SHALL search for API calls related to the failed CloudFormation operations
3. WHEN CloudTrail events are found, THE Error_Analyzer SHALL extract the responseElements message field
4. THE Error_Analyzer SHALL correlate CloudTrail events with CloudFormation stack operations by timestamp and resource identifiers

### Requirement 4: Error Message Extraction

**User Story:** As a developer, I want to see detailed error messages from CloudTrail responseElements, so that I can understand specific API failures.

#### Acceptance Criteria

1. THE Error_Analyzer SHALL parse CloudTrail log entries to extract responseElements data
2. WHEN responseElements contains a message field, THE Error_Analyzer SHALL display the detailed error message
3. THE Error_Analyzer SHALL handle cases where responseElements or message fields are missing
4. THE Error_Analyzer SHALL preserve the original error context including timestamps and API call details

### Requirement 5: Comprehensive Error Display

**User Story:** As a developer, I want to see all relevant error information in a clear format, so that I can quickly diagnose and fix CloudFormation issues.

#### Acceptance Criteria

1. THE Error_Analyzer SHALL display CloudFormation stack errors with timestamps and resource information
2. THE Error_Analyzer SHALL show corresponding CloudTrail error details when available
3. THE Error_Analyzer SHALL format output in a readable structure with clear error categorization
4. THE Error_Analyzer SHALL include both high-level CloudFormation errors and detailed CloudTrail messages in the same report

### Requirement 6: AWS SDK Integration

**User Story:** As a developer, I want the program to use AWS SDK Go v2, so that I can leverage the latest AWS API capabilities and authentication methods.

#### Acceptance Criteria

1. THE Error_Analyzer SHALL use AWS SDK Go v2 for all AWS service interactions
2. THE Error_Analyzer SHALL support standard AWS credential resolution (environment variables, profiles, IAM roles)
3. THE Error_Analyzer SHALL handle AWS API rate limiting and pagination appropriately
4. THE Error_Analyzer SHALL provide meaningful error messages for AWS authentication and permission issues

### Requirement 7: Time-Based Error Filtering

**User Story:** As a developer, I want to focus on recent errors by default while having the option to view all historical errors, so that I can quickly diagnose current issues or perform comprehensive historical analysis when needed.

#### Acceptance Criteria

1. WHEN no time filter flag is provided, THE Error_Analyzer SHALL analyze and display only errors that occurred within the last 1 hour
2. WHEN the --full flag is provided, THE Error_Analyzer SHALL analyze and display all available errors regardless of their age
3. THE Error_Analyzer SHALL filter both CloudFormation stack events and CloudTrail log queries based on the selected time range
4. THE Error_Analyzer SHALL display the time range being analyzed in the output to inform users of the scope