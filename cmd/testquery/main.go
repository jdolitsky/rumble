package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

var (
	GcloudProject = os.Getenv("GCLOUD_PROJECT")
	GcloudDataset = os.Getenv("GCLOUD_DATASET")
	GcloudTable   = os.Getenv("GCLOUD_TABLE")
)

type ImageCveScan struct {
	GithubIssueId int
	Image         string
	Digest        string
	Time          string
	Created       string
	Low           int      `bigquery:"low_cve_count"`
	Med           int      `bigquery:"med_cve_count"`
	High          int      `bigquery:"high_cve_count"`
	Crit          int      `bigquery:"crit_cve_count"`
	Negligible    int      `bigquery:"negligible_cve_count"`
	MatchesString string   `bigquery:"raw_grype_json"`
	Matches       []*Match `json:"matches"`
}

type Match struct {
	Vuln     Vulnerability `json:"vulnerability"`
	Nack     *Nack
	Artifact Artifact
}

type Vulnerability struct {
	CveId      string `json:"id"`
	Datasource string `json:"dataSource"`
	Severity   string
}

type Artifact struct {
	Name      string
	Version   string
	Type      string
	Locations *[]Locations
}

type Locations struct {
	Path    string
	LayerID string
}

type Nack struct {
	Url    *string
	Cve    string
	Reason string
}

func main() {
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, GcloudProject)
	imageScans := []*ImageCveScan{}
	if err != nil {
		log.Fatal("Failed while creating client:", err)
	}
	q := client.Query(`
		SELECT
		  *
		FROM (
		  SELECT
		    *,
		    ROW_NUMBER() OVER (PARTITION BY image ORDER BY time DESC) rn
		  FROM
		    ` + "`" + GcloudDataset + "." + GcloudTable + "`" + `
		  WHERE
		    scanner = "grype" ) t
		WHERE
		  rn = 1
		ORDER BY
		  image;
	`)
	it, err := q.Read(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for {
		var is ImageCveScan
		err := it.Next(&is)
		if is.MatchesString != "" {
			err = json.Unmarshal([]byte(is.MatchesString), &is)
			if err != nil {
				log.Fatal("Failed to unmarshal CVE match: ", err)
			}
		}
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		imageScans = append(imageScans, &is)
	}
	for _, scan := range imageScans {
		total := scan.Crit + scan.High + scan.Med + scan.Low + scan.Negligible
		if total > 0 {
			fmt.Println(scan.Image)
			fmt.Printf(" - Critical: %d\n", scan.Crit)
			fmt.Printf(" - High:     %d\n", scan.High)
			fmt.Printf(" - Medium:   %d\n", scan.Med)
			fmt.Printf(" - Low:      %d\n", scan.Low)
			fmt.Printf(" - Neg:      %d\n", scan.Negligible)
		}
	}
}
