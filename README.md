# CloudFormation Error Analyzer

A Go CLI tool that analyzes CloudFormation stack failures by correlating stack events with CloudTrail logs to reveal detailed error messages.

Use at your own risk. This tool is provided as-is without any warranty or support.

## Usage

```bash
# Analyze the most recent stack (today's errors only)
./cfn-analyzer

# Analyze a specific stack (today's errors only)
./cfn-analyzer <stack-name>
```

## Features

- Automatically finds and analyzes the most recent CloudFormation stack
- Extracts detailed error messages from CloudTrail logs for GeneralServiceException errors
- Filters to show only errors from today
- Correlates CloudFormation events with underlying AWS API failures

## Example Output

```
[Error 2]
Timestamp:     2026-01-08 09:38:59 UTC
Resource:      WisdomPromptsQUERYREFORMULATION
Resource Type: AWS::Wisdom::AIPrompt
Status:        CREATE_FAILED
Reason:        Resource handler returned message: "Error occurred during operation..."

CloudTrail Details:
Event Time:   2026-01-08 09:38:59 UTC
Event Name:   CreateAIPrompt
Event Source: qconnect.amazonaws.com
Error Code:   ConflictException
Detailed Message (from CloudTrail):
Name is already in use
```

## Requirements

- Go 1.25+
- AWS credentials configured (environment variables, profiles, or IAM roles)
- CloudTrail enabled in your AWS account
- Permissions: `cloudformation:DescribeStacks`, `cloudformation:DescribeStackEvents`, `cloudtrail:LookupEvents`

## Build

```bash
go build -o cfn-analyzer ./main
```

## Prebuild binary

See [Releases](https://github.com/megaproaktiv/cfnrc/releases) for prebuilt binaries.
