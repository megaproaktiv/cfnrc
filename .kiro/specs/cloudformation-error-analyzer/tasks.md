# Implementation Plan: CloudFormation Error Analyzer

## Overview

Implementation of a Go CLI application that analyzes CloudFormation stack errors by correlating them with CloudTrail logs. The project structure follows Go conventions with main.go in its own directory and packages in the root project directory.

## Tasks

- [x] 1. Set up project structure and dependencies
  - Create main directory with main.go
  - Initialize go.mod with required AWS SDK Go v2 dependencies
  - Create package directories for core functionality
  - _Requirements: 6.1_

- [x] 2. Implement CLI argument parsing and input validation
  - [x] 2.1 Create CLI handler in main directory
    - Parse command line arguments for stack name
    - Handle default case when no stack name provided
    - _Requirements: 1.1, 1.2_

  - [ ]* 2.2 Write property test for CLI argument parsing
    - **Property 1: Stack Name Input Validation**
    - **Validates: Requirements 1.1, 1.4**

  - [x] 2.3 Implement input validation package
    - Validate stack name format
    - Handle non-existent stack names with descriptive errors
    - _Requirements: 1.3, 1.4_

  - [ ]* 2.4 Write property test for input validation
    - **Property 3: Invalid Stack Error Handling**
    - **Validates: Requirements 1.3**

- [ ] 3. Implement CloudFormation integration
  - [x] 3.1 Create CloudFormation client package
    - Initialize AWS SDK Go v2 CloudFormation client
    - Implement stack event retrieval
    - _Requirements: 2.1, 6.1_

  - [x] 3.2 Implement latest stack detection
    - Find most recently updated CloudFormation stack
    - _Requirements: 1.2_

  - [ ]* 3.3 Write property test for default stack selection
    - **Property 2: Default Stack Selection**
    - **Validates: Requirements 1.2**

  - [x] 3.4 Create error extraction package
    - Extract errors from CloudFormation stack events
    - Identify GeneralServiceException errors
    - _Requirements: 2.2, 2.3_

  - [ ]* 3.5 Write property tests for error detection
    - **Property 4: Error Event Detection**
    - **Validates: Requirements 2.2**

  - [ ]* 3.6 Write property test for GeneralServiceException flagging
    - **Property 5: GeneralServiceException Flagging**
    - **Validates: Requirements 2.3**

- [x] 4. Checkpoint - Ensure CloudFormation integration works
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement CloudTrail integration
  - [x] 5.1 Create CloudTrail client package
    - Initialize AWS SDK Go v2 CloudTrail client
    - Implement CloudTrail event search functionality
    - _Requirements: 3.1, 3.2_

  - [x] 5.2 Implement responseElements extraction
    - Parse CloudTrail events for responseElements data
    - Extract message fields from responseElements
    - Handle missing or malformed data gracefully
    - _Requirements: 3.3, 4.1, 4.2, 4.3_

  - [ ]* 5.3 Write property test for CloudTrail query correlation
    - **Property 6: CloudTrail Query Correlation**
    - **Validates: Requirements 3.1, 3.2**

  - [ ]* 5.4 Write property test for responseElements extraction
    - **Property 7: ResponseElements Extraction**
    - **Validates: Requirements 3.3, 4.1**

  - [ ]* 5.5 Write property test for message field handling
    - **Property 9: Message Field Handling**
    - **Validates: Requirements 4.2, 4.3**

- [x] 6. Implement error correlation logic
  - [x] 6.1 Create error correlation package
    - Match CloudFormation errors with CloudTrail events by timestamp
    - Correlate events using resource identifiers
    - Preserve original error context
    - _Requirements: 3.4, 4.4_

  - [ ]* 6.2 Write property test for event correlation
    - **Property 8: Event Correlation**
    - **Validates: Requirements 3.4**

  - [ ]* 6.3 Write property test for context preservation
    - **Property 10: Context Preservation**
    - **Validates: Requirements 4.4**

- [x] 7. Implement output formatting and display
  - [x] 7.1 Create output formatter package
    - Format CloudFormation errors with timestamps and resource info
    - Display CloudTrail error details when available
    - Combine both error types in unified report
    - _Requirements: 2.4, 5.1, 5.2, 5.4_

  - [ ]* 7.2 Write property test for comprehensive error display
    - **Property 11: Comprehensive Error Display**
    - **Validates: Requirements 5.1, 5.2, 5.4**

- [x] 8. Implement AWS error handling
  - [x] 8.1 Add AWS authentication error handling
    - Handle credential resolution failures
    - Provide meaningful error messages for permission issues
    - _Requirements: 6.2, 6.4_

  - [ ]* 8.2 Write property test for AWS authentication error handling
    - **Property 12: AWS Authentication Error Handling**
    - **Validates: Requirements 6.4**

- [x] 9. Integration and main application wiring
  - [x] 9.1 Wire all components together in main.go
    - Orchestrate the complete analysis workflow
    - Handle command line execution and error reporting
    - _Requirements: All requirements_

  - [ ]* 9.2 Write integration tests
    - Test end-to-end analysis workflow
    - Test error scenarios and edge cases
    - _Requirements: All requirements_

- [ ] 10. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Project structure follows Go conventions with main.go in main/ directory
- Packages are created in root project directory
- Property tests validate universal correctness properties
- Integration tests validate complete workflow functionality