# # AWS Tags Updater

## Installation

```sh
wget https://github.com/PePoDev/aws-tags-updater/releases/download/v0.3.1/aws-tags-updater
chmod +x aws-tags-updater
mv aws-tags-updater /usr/local/bin
```

## Getting Started

> aws-tags-updater --help

```sh
AWS Tags Updater - Sync tags with all resources via sheet

Usage:
  aws-tags-updater [flags]

Flags:
  -i, --column-identifier string              Column to read identifier (default "Identifier")
  -t, --column-service-type string            Column to specific AWS service type (default "Service")
  -n, --column-tags-keys strings              Column name to get file to open (default [Name])
  -p, --column-tags-prefix column-tags-name   Column prefix to read as tags (Use with column-tags-name) (default "Tag:")
      --debug                                 Enable debug mode
  -f, --file string                           File to open
  -h, --help                                  help for aws-tags-updater
  -r, --region string                         AWS Region (default "ap-southeast-1")
  -s, --sheet string                          Sheet name
      --tags-ignore-value string              Value to ignore in tag column (default "(not tagged)")
```

> aws-tags-updater --file example.xlsx --sheet Sheet1 --column-tags-keys Name,Owner,Environment

## Supported Services

- EC2
- CertificateManager
- ~~CloudFormation~~
- CloudTrail
- Cloudwatch
- CodeArtifact
- Cognito
- ECS
- EFS
- EKS
- ElastiCache
- ElasticLoadBalancing
- ElasticLoadBalancingV2
- Events
- KMS
- Lambda
- RDS
- Route53Resolver
- S3
- SES
- SNS
- SSM
