package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xuri/excelize/v2"
)

var rootCmd = &cobra.Command{
	Use:   "aws-tags-updater",
	Short: "AWS Tags Updater - Sync tags with all resources via sheet",
	Long:  "AWS Tags Updater - Sync tags with all resources via sheet",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		file, err := excelize.OpenFile(viper.GetString("file"))
		if err != nil {
			logrus.Fatal(err)
		}

		rows, err := file.GetRows(viper.GetString("sheet"))
		if err != nil {
			logrus.Fatal(err)
		}

		var tagsFilter []string
		for _, v := range viper.GetStringSlice("column-tags-keys") {
			tagsFilter = append(tagsFilter, fmt.Sprintf("%s %s", viper.GetString("column-tags-prefix"), v))
		}
		logrus.Debugf("tags filter: %v", tagsFilter)

		var tagsFillterIds []int
		var identifier int
		var service int
		for i, row := range rows {
			for j, cell := range row {
				if i == 0 {
					if contains(tagsFilter, cell) {
						tagsFillterIds = append(tagsFillterIds, j)
					}
					if cell == viper.GetString("column-identifier") {
						identifier = j
					}
					if cell == viper.GetString("column-service-type") {
						service = j
					}
				}
				logrus.Debugf("row %d, column %d = %s", i, j, cell)
			}

			if i > 0 {
				tags := make(map[string]string)
				for _, v := range tagsFillterIds {
					if rows[i][v] != viper.GetString("tags-ignore-value") {
						tags[strings.Split(rows[0][v], " ")[1]] = rows[i][v]
					}
				}

				session, err := session.NewSession(&aws.Config{
					Region: aws.String(viper.GetString("region"))},
				)
				if err != nil {
					fmt.Println("Could not create instance", err)
					return
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

					svc := ec2.New(session)
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
				case "CloudFormation":
				case "CloudTrail":
				case "Cloudwatch":
				case "CodeArtifact":
				case "Cognito":
				case "ECS":
				case "EFS":
				case "EKS":
				case "ElastiCache":
				case "ElasticLoadBalancing":
				case "ElasticLoadBalancingV2":
				case "Events":
				case "KMS":
				case "Lambda":
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
					svc := rds.New(session)
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
				case "S3":
				case "SES":
				case "SNS":
				case "SSM":
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
