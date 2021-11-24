package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/rds"
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
		fileName := viper.GetString("file")
		sheetName := viper.GetString("sheet")
		region := viper.GetString("region")

		columnTagKeys := viper.GetStringSlice("column-tags-keys")
		columnTagPrefix := viper.GetString("column-tags-prefix")
		columnIdentifier := viper.GetString("column-identifier")
		columnServiceType := viper.GetString("column-service-type")
		tagsIgnoreValue := viper.GetString("tags-ignore-value")

		if debug {
			logrus.SetLevel(logrus.DebugLevel)
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
			fmt.Println("Credentials invalid:", err)
			return
		}

		stsSvc := sts.New(sess)
		req, result := stsSvc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
		err = req.Send()
		if err != nil {
			logrus.WithError(err).Fatal("failed to call stsSvc")
		}
		accountId := *result.Account
		logrus.Infof("AWS Account id: %s", accountId)

		var tagsFilter []string
		for _, v := range columnTagKeys {
			tagsFilter = append(tagsFilter, fmt.Sprintf("%s %s", columnTagPrefix, v))
		}
		logrus.Infof("Tags name to filter: [%v]", strings.Join(tagsFilter, ", "))

		var tagsFillterIds []int
		var identifier int
		var service int
		for i, row := range rows {
			for j, value := range row {
				if i == 0 {
					if value == columnIdentifier {
						logrus.Infof("Found column identifier [%s] at column [%d]", value, j)
						identifier = j
					}
					if contains(tagsFilter, value) {
						logrus.Infof("Found tags fillter [%s] at column [%d]", value, j)
						tagsFillterIds = append(tagsFillterIds, j)
					}
					if value == columnServiceType {
						logrus.Infof("Found column service type [%s] at column [%d]", value, j)
						service = j
					}
				}
				logrus.Debugf("row %d, column %d = %s", i, j, value)
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
						if v == "" {
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
						if v == "" {
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
					// newTags := []*cloudformation.Tag{}
					// for k, v := range tags {
					// 	if v == "" {
					// 		newTags = append(newTags, &cloudformation.Tag{
					// 			Key:   aws.String(k),
					// 			Value: aws.String(""),
					// 		})
					// 	} else {
					// 		newTags = append(newTags, &cloudformation.Tag{
					// 			Key:   aws.String(k),
					// 			Value: aws.String(v),
					// 		})
					// 	}
					// }

					// svc := cloudformation.New(sess)
					// _, err := svc.UpdateStack(&cloudformation.UpdateStackInput{
					// 	StackName:           &rows[i][identifier],
					// 	UsePreviousTemplate: aws.Bool(true),
					// 	Tags:                newTags,
					// })
					// if err != nil {
					// 	logrus.Errorf("Could not create tags for CloudFormation %v %v", rows[i][identifier], err)
					// 	continue
					// }
					logrus.Errorf("CloudFormation Not Implemented")
					continue
				case "CloudTrail":
					logrus.Errorf("CloudTrail Not Implemented")
					continue
				case "Cloudwatch":
					logrus.Errorf("Cloudwatch Not Implemented")
					continue
				case "CodeArtifact":
					logrus.Errorf("CodeArtifact Not Implemented")
					continue
				case "Cognito":
					logrus.Errorf("Cognito Not Implemented")
					continue
				case "ECS":
					logrus.Errorf("ECS Not Implemented")
					continue
				case "EFS":
					logrus.Errorf("EFS Not Implemented")
					continue
				case "EKS":
					logrus.Errorf("EKS Not Implemented")
					continue
				case "ElastiCache":
					logrus.Errorf("ElastiCache Not Implemented")
					continue
				case "ElasticLoadBalancing":
					logrus.Errorf("ElasticLoadBalancing Not Implemented")
					continue
				case "ElasticLoadBalancingV2":
					logrus.Errorf("ElasticLoadBalancingV2 Not Implemented")
					continue
				case "Events":
					logrus.Errorf("Events Not Implemented")
					continue
				case "KMS":
					logrus.Errorf("KMS Not Implemented")
					continue
				case "Lambda":
					logrus.Errorf("Lambda Not Implemented")
					continue
				case "RDS":
					rdsTags := []*rds.Tag{}
					rdsDeleteTags := []*string{}
					for k, v := range tags {
						if v == "" {
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
					logrus.Errorf("Route53Resolver Not Implemented")
					continue
				case "S3":
					logrus.Errorf("S3 Not Implemented")
					continue
				case "SES":
					logrus.Errorf("SES Not Implemented")
					continue
				case "SNS":
					snsTags := []*sns.Tag{}
					snsDeleteTags := []*string{}
					for k, v := range tags {
						if v == "" {
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
					// ssmTags := []*ssm.Tag{}
					// ssmDeleteTags := []*string{}
					// for k, v := range tags {
					// 	if v == "" {
					// 		ssmDeleteTags = append(ssmDeleteTags, aws.String(k))
					// 	} else {
					// 		ssmTags = append(ssmTags, &ssm.Tag{
					// 			Key:   aws.String(k),
					// 			Value: aws.String(v),
					// 		})
					// 	}
					// }
					// svc := ssm.New(sess)
					// _, err = svc.AddTagsToResource(&ssm.AddTagsToResourceInput{
					// 	ResourceId: aws.String(rows[i][identifier]),
					// 	// ResourceType: aws.String(""),
					// 	Tags: ssmTags,
					// })
					// if err != nil {
					// 	logrus.Errorf("Could not create tags for SSM %v %v", rows[i][identifier], err)
					// 	continue
					// }

					// if len(ssmDeleteTags) > 0 {
					// 	_, err = svc.RemoveTagsFromResource(&ssm.RemoveTagsFromResourceInput{
					// 		ResourceId: &rows[i][identifier],
					// 		TagKeys:    ssmDeleteTags,
					// 	})
					// 	if err != nil {
					// 		logrus.Errorf("Could not delete unused tags for SSM %v %v", rows[i][identifier], err)
					// 		continue
					// 	}
					// }
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
