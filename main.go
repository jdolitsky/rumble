package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/chainguard-dev/rumble/pkg/oci"
	"github.com/chainguard-dev/rumble/pkg/types"
)

const (
	attTypeVuln = "https://cosign.sigstore.dev/attestation/vuln/v1"
)

var (
	GcloudProject = os.Getenv("GCLOUD_PROJECT")
	GcloudDataset = os.Getenv("GCLOUD_DATASET")

	// This is the table that stores a row for each rumble run/scan
	GcloudTable = os.Getenv("GCLOUD_TABLE")

	// This is a table that holds individual vulns found in a single rumble run/scan
	// The scan_id field on this table refers to the rumble run id (acting as a foreign key)
	GcloudTableVulns = os.Getenv("GCLOUD_TABLE_VULNS")
)

func main() {
	image := flag.String("image", "cgr.dev/chainguard/static:latest", "OCI image")
	scanner := flag.String("scanner", "grype", "Which scanner to use, (\"trivy\" or \"grype\")")
	attest := flag.Bool("attest", false, "If enabled, attempt to attest vuln results using cosign")
	bigqueryUpload := flag.Bool("bigquery", true, "If enabled, attempt to upload results to BigQuery")
	invocationURI := flag.String("invocation-uri", "unknown", "in-toto value for invocation uri")
	invocationEventID := flag.String("invocation-event-id", "unknown", "in-toto value for invocation event_id")
	invocationBuilderID := flag.String("invocation-builder-id", "unknown", "in-toto value for invocation builder.id")
	dockerConfig := flag.String("docker-config", "", "explicit location of docker config directory")
	flag.Parse()

	// If the user is attesting, always use sarif format
	format := "json"
	if *attest {
		format = "sarif"
	}

	filename, startTime, endTime, summary, err := scanImage(*image, *scanner, format, *dockerConfig)
	defer os.Remove(filename)
	if err != nil {
		panic(err)
	}

	if *attest {
		fmt.Println("Attempting to attest scan results using cosign...")
		if err := attestImage(*image, startTime, endTime, *scanner, *invocationURI, *invocationEventID, *invocationBuilderID, filename, *dockerConfig); err != nil {
			panic(err)
		}
	} else {
		// Get the image created time
		created, buildTimeErr := oci.ImageBuildTime(*image)
		if buildTimeErr != nil {
			panic(buildTimeErr)
		}
		fmt.Printf("Image %s built at: %s\n", *image, created)
		if created != nil {
			summary.Created = created.Format(time.RFC3339)
		} else {
			summary.Created = "1970-01-01T00:00:00Z"
		}

		// Print the summary
		b, err := json.MarshalIndent(summary, "", "    ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(b))

		// Extract vulns from the raw scanner output
		vulns, err := summary.ExtractVulns()
		if err != nil {
			panic(err)
		}
		for _, vuln := range vulns {
			fmt.Printf("Adding vuln entry for \"%s %s %s %s %s\" (id=\"%s\")\n",
				vuln.Name, vuln.Installed, vuln.FixedIn, vuln.Vulnerability, vuln.Type, vuln.ID)
		}

		// Upload to BigQuery
		if *bigqueryUpload {
			summary.SetID()
			fmt.Printf("Adding 1 row to table \"%s\" (scan_id=\"%s\")\n", GcloudTable, summary.ID)
			ctx := context.Background()
			client, err := bigquery.NewClient(ctx, GcloudProject)
			if err != nil {
				panic(err)
			}
			dataset := client.Dataset(GcloudDataset)
			table := dataset.Table(GcloudTable)
			tableInserter := table.Inserter()
			if err := tableInserter.Put(ctx, summary); err != nil {
				panic(err)
			}

			// Add a row for each vuln found
			numVulns := len(vulns)
			if numVulns > 0 {
				fmt.Printf("Adding %d row(s) to table \"%s\"\n", numVulns, GcloudTableVulns)
				tableVulns := dataset.Table(GcloudTableVulns)
				tableVulnsInserter := tableVulns.Inserter()
				if err := tableVulnsInserter.Put(ctx, vulns); err != nil {
					panic(err)
				}
			}
		}
	}
}

func scanImage(image string, scanner string, format string, dockerConfig string) (string, *time.Time, *time.Time, *types.ImageScanSummary, error) {
	var filename string
	var startTime, endTime *time.Time
	var summary *types.ImageScanSummary
	var err error
	switch scanner {
	case "trivy":
		filename, startTime, endTime, summary, err = scanImageTrivy(image, format, dockerConfig)
	case "grype":
		filename, startTime, endTime, summary, err = scanImageGrype(image, format, dockerConfig)
	default:
		err = fmt.Errorf("invalid scanner: %s", scanner)
	}
	if err != nil {
		return "", nil, nil, nil, err
	}
	return filename, startTime, endTime, summary, nil
}

func attestImage(image string, startTime *time.Time, endTime *time.Time, scanner string, invocationURI string, invocationEventID string, invocationBuilderID string, filename string, dockerConfig string) error {
	env := os.Environ()
	if dockerConfig != "" {
		env = append(env, fmt.Sprintf("DOCKER_CONFIG=%s", dockerConfig))
	}

	// Convert the sarif document to InToto statement
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var sarifObj types.SarifOutput
	if err := json.Unmarshal(b, &sarifObj); err != nil {
		return err
	}

	if len(sarifObj.Runs) == 0 {
		return fmt.Errorf("issue with grype sarif output")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return err
	}

	statement := types.InTotoStatement{
		Invocation: types.InTotoStatementInvocation{
			URI:       invocationURI,
			EventID:   invocationEventID,
			BuilderID: invocationBuilderID,
		},
		Scanner: types.InTotoStatementScanner{
			URI:     sarifObj.Runs[0].Tool.Driver.InformationURI,
			Version: sarifObj.Runs[0].Tool.Driver.Version,
			Result:  result,
		},
		Metadata: types.InTotoStatementMetadata{
			ScanStartedOn:  startTime.UTC().Format("2006-01-02T15:04:05Z"),
			ScanFinishedOn: endTime.UTC().Format("2006-01-02T15:04:05Z"),
		},
	}

	b, err = json.MarshalIndent(statement, "", "    ")
	if err != nil {
		return err
	}

	// Overwrite the sarif file with the intoto envelope file
	if err := os.WriteFile(filename, b, 0644); err != nil {
		return err
	}
	fmt.Println(string(b))

	// Attest
	args := []string{"attest", "--yes", "--type", attTypeVuln, "--predicate", filename, image}
	cmd := exec.Command("cosign", args...)
	fmt.Printf("Running attestation command \"cosign %s\"...\n", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return err
	}

	// Verify (only warn on error since we may not be able to verify private images)
	// TODO: pass in the signing identity vs using star for regex
	args = []string{"verify-attestation", "--type", attTypeVuln,
		"--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*", image}
	cmd = exec.Command("cosign", args...)
	fmt.Printf("Running verify command \"cosign %s\"...\n", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		fmt.Printf("WARNING: Could not verify attestation (is this a private image?): %s\n", err.Error())
	}
	return nil
}

func scanImageTrivy(image string, format string, dockerConfig string) (string, *time.Time, *time.Time, *types.ImageScanSummary, error) {
	log.Printf("scanning %s with trivy\n", image)
	file, err := os.CreateTemp("", "trivy-scan-")
	if err != nil {
		return "", nil, nil, nil, err
	}
	env := os.Environ()
	if dockerConfig != "" {
		env = append(env, fmt.Sprintf("DOCKER_CONFIG=%s", dockerConfig))
	}
	args := []string{"--debug", "image", "--timeout", "15m", "--offline-scan", "-f", format, "-o", file.Name(), image}
	fmt.Printf("Running scan command \"trivy %s\"...\n", strings.Join(args, " "))
	cmd := exec.Command("trivy", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	startTime := time.Now()
	if err := cmd.Run(); err != nil {
		return "", nil, nil, nil, err
	}
	endTime := time.Now()
	b, err := os.ReadFile(file.Name())
	if err != nil {
		return "", nil, nil, nil, err
	}
	fmt.Println(string(b))

	// Get the trivy version
	var out bytes.Buffer
	cmd = exec.Command("trivy", "--version", "-f", "json")
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return "", nil, nil, nil, err
	}
	var trivyVersion types.TrivyVersionOutput
	if err := json.Unmarshal(out.Bytes(), &trivyVersion); err != nil {
		return "", nil, nil, nil, err
	}
	if format == "json" {
		var output types.TrivyScanOutput
		if err := json.Unmarshal(b, &output); err != nil {
			return "", nil, nil, nil, err
		}
		summary := trivyOutputToSummary(image, startTime, &output, &trivyVersion)
		return file.Name(), &startTime, &endTime, summary, err
	}
	return file.Name(), &startTime, &endTime, nil, nil
}

func scanImageGrype(image string, format string, dockerConfig string) (string, *time.Time, *time.Time, *types.ImageScanSummary, error) {
	log.Printf("scanning %s with grype\n", image)
	file, err := os.CreateTemp("", "grype-scan-")
	if err != nil {
		return "", nil, nil, nil, err
	}
	env := os.Environ()
	if dockerConfig != "" {
		env = append(env, fmt.Sprintf("DOCKER_CONFIG=%s", dockerConfig))
	}
	args := []string{"-v", "-o", format, "--file", file.Name(), image}
	fmt.Printf("Running scan command \"grype %s\"...\n", strings.Join(args, " "))
	cmd := exec.Command("grype", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	startTime := time.Now()
	if err := cmd.Run(); err != nil {
		return "", nil, nil, nil, err
	}
	endTime := time.Now()
	b, err := os.ReadFile(file.Name())
	if err != nil {
		return "", nil, nil, nil, err
	}
	fmt.Println(string(b))
	// Only attempt summary if the format is JSON
	if format == "json" {
		var output types.GrypeScanOutput
		if err := json.Unmarshal(b, &output); err != nil {
			return "", nil, nil, nil, err
		}
		summary := grypeOutputToSummary(image, startTime, &output)

		// Inject the raw Grype JSON output (minified)
		var buff *bytes.Buffer = new(bytes.Buffer)
		if err := json.Compact(buff, b); err != nil {
			return "", nil, nil, nil, err
		}
		summary.RawGrypeJSON = buff.String()

		return file.Name(), &startTime, &endTime, summary, err
	}
	return file.Name(), &startTime, &endTime, nil, nil
}

func grypeOutputToSummary(image string, scanTime time.Time, output *types.GrypeScanOutput) *types.ImageScanSummary {
	summary := &types.ImageScanSummary{
		Image:   image,
		Scanner: "grype",
		Time:    scanTime.UTC().Format("2006-01-02T15:04:05Z"),
	}

	summary.Success = true
	summary.ScannerVersion = output.Descriptor.Version
	summary.ScannerDbVersion = output.Descriptor.Db.Checksum

	// TODO: get the digest beforehand
	summary.Digest = strings.Split(output.Source.Target.RepoDigests[0], "@")[1]

	// CVE counts by severity
	summary.TotCveCount = len(output.Matches)
	for _, match := range output.Matches {
		switch match.Vulnerability.Severity {
		case "Low":
			summary.LowCveCount++
		case "Medium":
			summary.MedCveCount++
		case "High":
			summary.HighCveCount++
		case "Critical":
			summary.CritCveCount++
		case "Negligible":
			summary.NegligibleCveCount++
		case "Unknown":
			summary.UnknownCveCount++
		default:
			fmt.Printf("WARNING: unknown severity: %s\n", match.Vulnerability.Severity)
		}
	}
	return summary
}

func trivyOutputToSummary(image string, scanTime time.Time, output *types.TrivyScanOutput, trivyVersion *types.TrivyVersionOutput) *types.ImageScanSummary {
	summary := &types.ImageScanSummary{
		Image:              image,
		Scanner:            "trivy",
		Time:               scanTime.UTC().Format("2006-01-02T15:04:05Z"),
		NegligibleCveCount: 0, // This is only available in Grype output
	}

	summary.Success = true
	summary.ScannerVersion = trivyVersion.Version
	summary.ScannerDbVersion = trivyVersion.VulnerabilityDB.UpdatedAt

	// TODO: get the digest beforehand
	summary.Digest = strings.Split(output.Metadata.RepoDigests[0], "@")[1]

	// CVE counts by severity
	totalCveCount := 0
	for _, result := range output.Results {
		for _, vuln := range result.Vulnerabilities {
			totalCveCount++
			switch vuln.Severity {
			case "LOW":
				summary.LowCveCount++
			case "MEDIUM":
				summary.MedCveCount++
			case "HIGH":
				summary.HighCveCount++
			case "CRITICAL":
				summary.CritCveCount++
			case "UNKNOWN":
				summary.UnknownCveCount++
			default:
				fmt.Printf("WARNING: unknown severity: %s\n", vuln.Severity)
			}
		}
	}
	summary.TotCveCount = totalCveCount
	return summary
}
