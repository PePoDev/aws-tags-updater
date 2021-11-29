package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/aws/aws-sdk-go/service/codeartifact"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/efs"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elbv2"
	elb "github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/route53resolver"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xuri/excelize/v2"
)

var rootCmd = &cobra.Command{
	Use:   "aws-tags-updater",
	Short: "AWS Tags Updater - Sync tags with all resources via sheet",
	Run: func(cmd *cobra.Command, args []string) {
		debug := viper.GetBool("debug")
		trace := viper.GetBool("trace")
		fileName := viper.GetString("file")
		sheetName := viper.GetString("sheet")
		region := viper.GetString("region")

		columnTagKeys := viper.GetStringSlice("column-tags-keys")
		columnTagPrefix := viper.GetString("column-tags-prefix")
		columnIdentifier := viper.GetString("column-identifier")
		columnServiceType := viper.GetString("column-service-type")
		tagsIgnoreValue := viper.GetString("tags-ignore-value")
		deleteTagValue := ""

		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if trace {
			logrus.SetLevel(logrus.TraceLevel)
		}

		file, err := excelize.OpenFile(fileName)
		if err != nil {
			logrus.Fatal(err)
		}

		rows, err := file.GetRows(sheetName)
		if err != nil {
			logrus.Fatalln("Get rows error:", err)
		}

		sess, err := session.NewSession(&aws.Config{
			Region:                        aws.String(region),
			CredentialsChainVerboseErrors: aws.Bool(debug),
		})
		if err != nil {
			logrus.Fatalln("Credentials invalid: ", err)
		}

		stsSvc := sts.New(sess)
		req, result := stsSvc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
		err = req.Send()
		if err != nil {
			logrus.WithError(err).Fatal("failed to call stsSvc")
		}
		accountId := *result.Account
		logrus.Debugf("AWS Account id: %s", accountId)

		var tagsFilter []string
		for _, v := range columnTagKeys {
			tagsFilter = append(tagsFilter, fmt.Sprintf("%s %s", columnTagPrefix, v))
		}
		logrus.Debugf("Tags name to filter: [%v]", strings.Join(tagsFilter, ", "))

		var tagsFillterIds []int
		var identifier int
		var service int
		for i, row := range rows {
			for j, value := range row {
				if i == 0 {
					if value == columnIdentifier {
						logrus.Debugf("Found column identifier [%s] at column [%d]", value, j)
						identifier = j
					}
					if contains(tagsFilter, value) {
						logrus.Debugf("Found tags fillter [%s] at column [%d]", value, j)
						tagsFillterIds = append(tagsFillterIds, j)
					}
					if value == columnServiceType {
						logrus.Debugf("Found column service type [%s] at column [%d]", value, j)
						service = j
					}
				}
				logrus.Tracef("row %d, column %d = %s", i, j, value)
			}

			if i > 0 {
				tags := make(map[string]string)
				for _, v := range tagsFillterIds {
					if rows[i][v] != tagsIgnoreValue {
						tags[strings.Split(rows[0][v], " ")[1]] = rows[i][v]
					}
				}

				switch rows[i][service] {
				case "EC2":
					ec2tags := []*ec2.Tag{}
					ec2deleteTags := []*ec2.Tag{}
					for k, v := range tags {
						if v == deleteTagValue {
							ec2deleteTags = append(ec2deleteTags, &ec2.Tag{
								Key: aws.String(k),
							})
						} else {
							ec2tags = append(ec2tags, &ec2.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}

					svc := ec2.New(sess)
					_, err := svc.CreateTags(&ec2.CreateTagsInput{
						Resources: []*string{&rows[i][identifier]},
						Tags:      ec2tags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for instance %v %v", rows[i][identifier], err)
						continue
					}

					if len(ec2deleteTags) > 0 {
						_, err = svc.DeleteTags(&ec2.DeleteTagsInput{
							Resources: []*string{&rows[i][identifier]},
							Tags:      ec2deleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for instance %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "CertificateManager":
					acmTags := []*acm.Tag{}
					acmDeleteTags := []*acm.Tag{}
					for k, v := range tags {
						if v == deleteTagValue {
							acmDeleteTags = append(acmDeleteTags, &acm.Tag{
								Key: aws.String(k),
							})
						} else {
							acmTags = append(acmTags, &acm.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}

					acmArn := aws.String(fmt.Sprintf("arn:aws:acm:%s:%s:certificate/%s", region, accountId, rows[i][identifier]))
					svc := acm.New(sess)
					_, err := svc.AddTagsToCertificate(&acm.AddTagsToCertificateInput{
						CertificateArn: acmArn,
						Tags:           acmTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for certificate %v %v", rows[i][identifier], err)
						continue
					}

					if len(acmDeleteTags) > 0 {
						_, err = svc.RemoveTagsFromCertificate(&acm.RemoveTagsFromCertificateInput{
							CertificateArn: acmArn,
							Tags:           acmDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for certificate %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "CloudFormation":
					logrus.Errorf("CloudFormation Not Implemented")
					continue
				case "CloudTrail":
					cloudtrailTags := []*cloudtrail.Tag{}
					cloudtrailDeleteTags := []*cloudtrail.Tag{}
					for k, v := range tags {
						if v == deleteTagValue {
							cloudtrailDeleteTags = append(cloudtrailDeleteTags, &cloudtrail.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						} else {
							cloudtrailTags = append(cloudtrailTags, &cloudtrail.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := cloudtrail.New(sess)
					_, err = svc.AddTags(&cloudtrail.AddTagsInput{
						ResourceId: aws.String(rows[i][identifier]),
						TagsList:   cloudtrailTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Cloud Trail %v %v", rows[i][identifier], err)
						continue
					}

					if len(cloudtrailDeleteTags) > 0 {
						_, err = svc.RemoveTags(&cloudtrail.RemoveTagsInput{
							ResourceId: aws.String(rows[i][identifier]),
							TagsList:   cloudtrailDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Cloud Trail %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "Cloudwatch":
					cloudWatchTags := []*cloudwatch.Tag{}
					cloudWatchDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							cloudWatchDeleteTags = append(cloudWatchDeleteTags, aws.String(k))
						} else {
							cloudWatchTags = append(cloudWatchTags, &cloudwatch.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := cloudwatch.New(sess)
					_, err = svc.TagResource(&cloudwatch.TagResourceInput{
						ResourceARN: aws.String(rows[i][identifier]),
						Tags:        cloudWatchTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Cloud Watch %v %v", rows[i][identifier], err)
						continue
					}

					if len(cloudWatchDeleteTags) > 0 {
						_, err = svc.UntagResource(&cloudwatch.UntagResourceInput{
							ResourceARN: aws.String(rows[i][identifier]),
							TagKeys:     cloudWatchDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Cloud Watch %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "CodeArtifact":
					codeArtifactTags := []*codeartifact.Tag{}
					codeArtifactDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							codeArtifactDeleteTags = append(codeArtifactDeleteTags, aws.String(k))
						} else {
							codeArtifactTags = append(codeArtifactTags, &codeartifact.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := codeartifact.New(sess)
					_, err = svc.TagResource(&codeartifact.TagResourceInput{
						ResourceArn: aws.String(rows[i][identifier]),
						Tags:        codeArtifactTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Code Artifact %v %v", rows[i][identifier], err)
						continue
					}

					if len(codeArtifactDeleteTags) > 0 {
						_, err = svc.UntagResource(&codeartifact.UntagResourceInput{
							ResourceArn: aws.String(rows[i][identifier]),
							TagKeys:     codeArtifactDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Code Artifact %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "Cognito":
					cognitoTags := map[string]*string{}
					cognitoDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							cognitoDeleteTags = append(cognitoDeleteTags, aws.String(k))
						} else {
							cognitoTags[k] = aws.String(v)
						}
					}
					svc := cognitoidentity.New(sess)
					_, err = svc.TagResource(&cognitoidentity.TagResourceInput{
						ResourceArn: aws.String(rows[i][identifier]),
						Tags:        cognitoTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Cognito %v %v", rows[i][identifier], err)
						continue
					}

					if len(cognitoDeleteTags) > 0 {
						_, err = svc.UntagResource(&cognitoidentity.UntagResourceInput{
							ResourceArn: aws.String(rows[i][identifier]),
							TagKeys:     cognitoDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Cognito %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "ECS":
					ecsTags := []*ecs.Tag{}
					ecsDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							ecsDeleteTags = append(ecsDeleteTags, aws.String(k))
						} else {
							ecsTags = append(ecsTags, &ecs.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := ecs.New(sess)
					_, err = svc.TagResource(&ecs.TagResourceInput{
						ResourceArn: aws.String(rows[i][identifier]),
						Tags:        ecsTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for ECS %v %v", rows[i][identifier], err)
						continue
					}

					if len(ecsDeleteTags) > 0 {
						_, err = svc.UntagResource(&ecs.UntagResourceInput{
							ResourceArn: aws.String(rows[i][identifier]),
							TagKeys:     ecsDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for ECS %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "EFS":
					efsTags := []*efs.Tag{}
					efsDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							efsDeleteTags = append(efsDeleteTags, aws.String(k))
						} else {
							efsTags = append(efsTags, &efs.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := efs.New(sess)
					_, err = svc.TagResource(&efs.TagResourceInput{
						ResourceId: aws.String(rows[i][identifier]),
						Tags:       efsTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for EFS %v %v", rows[i][identifier], err)
						continue
					}

					if len(efsDeleteTags) > 0 {
						_, err = svc.UntagResource(&efs.UntagResourceInput{
							ResourceId: aws.String(rows[i][identifier]),
							TagKeys:    efsDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for EFS %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "EKS":
					eksTags := map[string]*string{}
					eksDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							eksDeleteTags = append(eksDeleteTags, aws.String(k))
						} else {
							eksTags[k] = aws.String(v)
						}
					}
					svc := eks.New(sess)
					_, err = svc.TagResource(&eks.TagResourceInput{
						ResourceArn: aws.String(rows[i][identifier]),
						Tags:        eksTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for EKS %v %v", rows[i][identifier], err)
						continue
					}

					if len(eksDeleteTags) > 0 {
						_, err = svc.UntagResource(&eks.UntagResourceInput{
							ResourceArn: aws.String(rows[i][identifier]),
							TagKeys:     eksDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for EKS %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "ElastiCache":
					elasticacheTags := []*elasticache.Tag{}
					elasticacheDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							elasticacheDeleteTags = append(elasticacheDeleteTags, aws.String(k))
						} else {
							elasticacheTags = append(elasticacheTags, &elasticache.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := elasticache.New(sess)
					_, err = svc.AddTagsToResource(&elasticache.AddTagsToResourceInput{
						ResourceName: aws.String(rows[i][identifier]),
						Tags:         elasticacheTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Elasticache %v %v", rows[i][identifier], err)
						continue
					}

					if len(elasticacheDeleteTags) > 0 {
						_, err = svc.RemoveTagsFromResource(&elasticache.RemoveTagsFromResourceInput{
							ResourceName: aws.String(rows[i][identifier]),
							TagKeys:      elasticacheDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Elasticache %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "ElasticLoadBalancing":
					elbTags := []*elb.Tag{}
					elbDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							elbDeleteTags = append(elbDeleteTags, aws.String(k))
						} else {
							elbTags = append(elbTags, &elb.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := elb.New(sess)
					_, err = svc.AddTags(&elb.AddTagsInput{
						ResourceArns: aws.StringSlice([]string{rows[i][identifier]}),
						Tags:         elbTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Elastic Load Balancing %v %v", rows[i][identifier], err)
						continue
					}

					if len(elbDeleteTags) > 0 {
						_, err = svc.RemoveTags(&elb.RemoveTagsInput{
							ResourceArns: aws.StringSlice([]string{rows[i][identifier]}),
							TagKeys:      elbDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Elastic Load Balancing %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "ElasticLoadBalancingV2":
					elbv2Tags := []*elbv2.Tag{}
					elbv2DeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							elbv2DeleteTags = append(elbv2DeleteTags, aws.String(k))
						} else {
							elbv2Tags = append(elbv2Tags, &elbv2.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := elbv2.New(sess)
					_, err = svc.AddTags(&elbv2.AddTagsInput{
						ResourceArns: aws.StringSlice([]string{rows[i][identifier]}),
						Tags:         elbv2Tags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Elastic Load Balancing V2 %v %v", rows[i][identifier], err)
						continue
					}

					if len(elbv2DeleteTags) > 0 {
						_, err = svc.RemoveTags(&elbv2.RemoveTagsInput{
							ResourceArns: aws.StringSlice([]string{rows[i][identifier]}),
							TagKeys:      elbv2DeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Elastic Load Balancing V2 %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "Events":
					cloudwatchEventsTags := []*cloudwatchevents.Tag{}
					cloudwatchEventsDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							cloudwatchEventsDeleteTags = append(cloudwatchEventsDeleteTags, aws.String(k))
						} else {
							cloudwatchEventsTags = append(cloudwatchEventsTags, &cloudwatchevents.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := cloudwatchevents.New(sess)
					_, err = svc.TagResource(&cloudwatchevents.TagResourceInput{
						ResourceARN: aws.String(rows[i][identifier]),
						Tags:        cloudwatchEventsTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Cloudwatch Events %v %v", rows[i][identifier], err)
						continue
					}

					if len(cloudwatchEventsDeleteTags) > 0 {
						_, err = svc.UntagResource(&cloudwatchevents.UntagResourceInput{
							ResourceARN: &rows[i][identifier],
							TagKeys:     cloudwatchEventsDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Cloudwatch Events %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "KMS":
					kmsTags := []*kms.Tag{}
					kmsDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							kmsDeleteTags = append(kmsDeleteTags, aws.String(k))
						} else {
							kmsTags = append(kmsTags, &kms.Tag{
								TagKey:   aws.String(k),
								TagValue: aws.String(v),
							})
						}
					}
					svc := kms.New(sess)
					_, err = svc.TagResource(&kms.TagResourceInput{
						KeyId: aws.String(rows[i][identifier]),
						Tags:  kmsTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for KMS %v %v", rows[i][identifier], err)
						continue
					}

					if len(kmsDeleteTags) > 0 {
						_, err = svc.UntagResource(&kms.UntagResourceInput{
							KeyId:   &rows[i][identifier],
							TagKeys: kmsDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for KMS %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "Lambda":
					lambdaTags := map[string]*string{}
					lambdaDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							lambdaDeleteTags = append(lambdaDeleteTags, aws.String(k))
						} else {
							lambdaTags[k] = aws.String(v)
						}
					}
					svc := lambda.New(sess)
					_, err = svc.TagResource(&lambda.TagResourceInput{
						Resource: aws.String(rows[i][identifier]),
						Tags:     lambdaTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Lambda %v %v", rows[i][identifier], err)
						continue
					}

					if len(lambdaDeleteTags) > 0 {
						_, err = svc.UntagResource(&lambda.UntagResourceInput{
							Resource: &rows[i][identifier],
							TagKeys:  lambdaDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Lambda %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "RDS":
					rdsTags := []*rds.Tag{}
					rdsDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							rdsDeleteTags = append(rdsDeleteTags, aws.String(k))
						} else {
							rdsTags = append(rdsTags, &rds.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := rds.New(sess)
					_, err = svc.AddTagsToResource(&rds.AddTagsToResourceInput{
						ResourceName: aws.String(rows[i][identifier]),
						Tags:         rdsTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for RDS %v %v", rows[i][identifier], err)
						continue
					}

					if len(rdsDeleteTags) > 0 {
						_, err = svc.RemoveTagsFromResource(&rds.RemoveTagsFromResourceInput{
							ResourceName: &rows[i][identifier],
							TagKeys:      rdsDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for RDS %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "Route53Resolver":
					route53resolverTags := []*route53resolver.Tag{}
					route53resolverDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							route53resolverDeleteTags = append(route53resolverDeleteTags, aws.String(k))
						} else {
							route53resolverTags = append(route53resolverTags, &route53resolver.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := route53resolver.New(sess)
					_, err = svc.TagResource(&route53resolver.TagResourceInput{
						ResourceArn: aws.String(rows[i][identifier]),
						Tags:        route53resolverTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for Route53Resolver %v %v", rows[i][identifier], err)
						continue
					}

					if len(route53resolverDeleteTags) > 0 {
						_, err = svc.UntagResource(&route53resolver.UntagResourceInput{
							ResourceArn: &rows[i][identifier],
							TagKeys:     route53resolverDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for Route53Resolver %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "S3":
					s3Tags := []*s3.Tag{}
					s3DeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							s3DeleteTags = append(s3DeleteTags, aws.String(k))
						} else {
							s3Tags = append(s3Tags, &s3.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := s3.New(sess)
					_, err = svc.PutBucketTagging(&s3.PutBucketTaggingInput{
						Bucket: aws.String(rows[i][identifier]),
						Tagging: &s3.Tagging{
							TagSet: s3Tags,
						},
					})
					if err != nil {
						logrus.Errorf("Could not create tags for S3 %v %v", rows[i][identifier], err)
						continue
					}

					if len(s3DeleteTags) > 0 {
						logrus.Errorf("Can't delete unused tags for S3 %v %v", rows[i][identifier], err)
						continue
					}
				case "SES":
					logrus.Errorf("SES Not Implemented")
					continue
				case "SNS":
					snsTags := []*sns.Tag{}
					snsDeleteTags := []*string{}
					for k, v := range tags {
						if v == deleteTagValue {
							snsDeleteTags = append(snsDeleteTags, aws.String(k))
						} else {
							snsTags = append(snsTags, &sns.Tag{
								Key:   aws.String(k),
								Value: aws.String(v),
							})
						}
					}
					svc := sns.New(sess)
					_, err = svc.TagResource(&sns.TagResourceInput{
						ResourceArn: aws.String(rows[i][identifier]),
						Tags:        snsTags,
					})
					if err != nil {
						logrus.Errorf("Could not create tags for SNS %v %v", rows[i][identifier], err)
						continue
					}

					if len(snsDeleteTags) > 0 {
						_, err = svc.UntagResource(&sns.UntagResourceInput{
							ResourceArn: &rows[i][identifier],
							TagKeys:     snsDeleteTags,
						})
						if err != nil {
							logrus.Errorf("Could not delete unused tags for SNS %v %v", rows[i][identifier], err)
							continue
						}
					}
				case "SSM":
					logrus.Errorf("SSM Not Implemented")
					continue
				default:
					logrus.Error("Service type not supported ", rows[i][service])
					continue
				}

				logrus.Infof("Changed %s \t id: %20s \t %v", rows[i][service], rows[i][identifier], tags)
			}
		}
		logrus.Debugf("Tags ids: %v", tagsFillterIds)
		logrus.Debugf("Identifier: %d", identifier)
		logrus.Debugf("Service: %d", service)
	},
}

func init() {
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetEnvPrefix("atu")
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().StringP("file", "f", "", "File to open")
	rootCmd.PersistentFlags().StringP("sheet", "s", "", "Sheet name")
	rootCmd.PersistentFlags().StringP("region", "r", "ap-southeast-1", "AWS Region")
	rootCmd.PersistentFlags().StringP("column-identifier", "i", "Identifier", "Column to read identifier")
	rootCmd.PersistentFlags().StringP("column-tags-prefix", "p", "Tag:", "Column prefix to read as tags (Use with `column-tags-name`)")
	rootCmd.PersistentFlags().StringSliceP("column-tags-keys", "n", []string{"Name"}, "Column name to get file to open")
	rootCmd.PersistentFlags().StringP("column-service-type", "t", "Service", "Column to specific AWS service type")
	rootCmd.PersistentFlags().String("tags-ignore-value", "(not tagged)", "Value to ignore in tag column")
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug mode")
	rootCmd.PersistentFlags().Bool("trace", false, "Enable trace mode")
	viper.BindPFlags(rootCmd.PersistentFlags())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(os.Stderr, err)
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
