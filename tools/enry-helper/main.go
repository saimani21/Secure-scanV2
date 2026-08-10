package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	enry "github.com/go-enry/go-enry/v2"
)

const (
	schemaVersion          = "1.0.0"
	helperVersion          = "0.2.3"
	enryVersion            = "v2.9.6"
	maxRequestCount        = 50_000
	maxDecodedContentBytes = 1024 * 1024
	maxInputLineBytes      = 2 * 1024 * 1024
	maxRelativePathBytes   = 4096
	maxRequestIDBytes      = 128
)

type classifyRequest struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	RelativePath  string `json:"relative_path"`
	ContentBase64 string `json:"content_base64"`
}

type classifyResponse struct {
	SchemaVersion      string   `json:"schema_version"`
	HelperVersion      string   `json:"helper_version"`
	EnryVersion        string   `json:"enry_version"`
	OK                 bool     `json:"ok"`
	RequestID          string   `json:"request_id"`
	RelativePath       string   `json:"relative_path"`
	ErrorCode          string   `json:"error_code,omitempty"`
	Language           string   `json:"language"`
	CandidateLanguages []string `json:"candidate_languages"`
	IsBinary           bool     `json:"is_binary"`
	IsVendor           bool     `json:"is_vendor"`
	IsGenerated        bool     `json:"is_generated"`
	IsTest             bool     `json:"is_test"`
	IsConfiguration    bool     `json:"is_configuration"`
	IsDocumentation    bool     `json:"is_documentation"`
	IsDotFile          bool     `json:"is_dot_file"`
	IsImage            bool     `json:"is_image"`
}

func validRequestID(value string) bool {
	if value == "" || len(value) > maxRequestIDBytes {
		return false
	}

	for _, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("._:-", character)

		if !valid {
			return false
		}
	}

	return true
}

func validRelativePath(value string) bool {
	if value == "" ||
		len([]byte(value)) > maxRelativePathBytes ||
		!utf8.ValidString(value) ||
		strings.Contains(value, "\\") ||
		strings.HasPrefix(value, "/") {
		return false
	}

	for _, character := range value {
		if character < 32 || character == 127 {
			return false
		}
	}

	cleaned := path.Clean(value)

	if cleaned != value ||
		cleaned == "." ||
		cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") {
		return false
	}

	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}

	return true
}

func emptyResponse() classifyResponse {
	return classifyResponse{
		SchemaVersion:      schemaVersion,
		HelperVersion:      helperVersion,
		EnryVersion:        enryVersion,
		CandidateLanguages: []string{},
	}
}

func errorResponse(code string) classifyResponse {
	response := emptyResponse()
	response.OK = false
	response.ErrorCode = code
	return response
}

func decodeRequest(line []byte) (classifyRequest, []byte, string) {
	var request classifyRequest

	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		return classifyRequest{}, nil, "INVALID_JSON"
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return classifyRequest{}, nil, "INVALID_JSON"
	}

	if request.SchemaVersion != schemaVersion {
		return classifyRequest{}, nil, "UNSUPPORTED_SCHEMA"
	}

	if !validRequestID(request.RequestID) {
		return classifyRequest{}, nil, "INVALID_REQUEST_ID"
	}

	if !validRelativePath(request.RelativePath) {
		return classifyRequest{}, nil, "INVALID_RELATIVE_PATH"
	}

	maxEncodedBytes := base64.StdEncoding.EncodedLen(maxDecodedContentBytes)
	if len(request.ContentBase64) > maxEncodedBytes {
		return classifyRequest{}, nil, "CONTENT_LIMIT_EXCEEDED"
	}

	content, err := base64.StdEncoding.Strict().DecodeString(
		request.ContentBase64,
	)
	if err != nil {
		return classifyRequest{}, nil, "INVALID_CONTENT"
	}

	if len(content) > maxDecodedContentBytes {
		return classifyRequest{}, nil, "CONTENT_LIMIT_EXCEEDED"
	}

	return request, content, ""
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	sort.Strings(result)
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}

func classify(request classifyRequest, content []byte) classifyResponse {
	response := emptyResponse()
	response.OK = true
	response.RequestID = request.RequestID
	response.RelativePath = request.RelativePath

	response.IsBinary = enry.IsBinary(content)
	response.IsVendor = enry.IsVendor(request.RelativePath)
	response.IsGenerated = enry.IsGenerated(
		request.RelativePath,
		content,
	)
	response.IsTest = enry.IsTest(request.RelativePath)
	response.IsConfiguration = enry.IsConfiguration(
		request.RelativePath,
	)
	response.IsDocumentation = enry.IsDocumentation(
		request.RelativePath,
	)
	response.IsDotFile = enry.IsDotFile(request.RelativePath)
	response.IsImage = enry.IsImage(request.RelativePath)

	if response.IsBinary {
		return response
	}

	response.Language = enry.GetLanguage(
		request.RelativePath,
		content,
	)
	response.CandidateLanguages = uniqueSorted(
		enry.GetLanguages(
			request.RelativePath,
			content,
		),
	)

	if response.Language != "" &&
		!contains(response.CandidateLanguages, response.Language) {
		response.CandidateLanguages = append(
			response.CandidateLanguages,
			response.Language,
		)
		sort.Strings(response.CandidateLanguages)
	}

	return response
}

func processLine(line []byte) classifyResponse {
	request, content, errorCode := decodeRequest(line)
	if errorCode != "" {
		return errorResponse(errorCode)
	}

	return classify(request, content)
}

func run(
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) int {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(
		make([]byte, 64*1024),
		maxInputLineBytes,
	)

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)

	requestCount := 0

	for scanner.Scan() {
		requestCount++
		if requestCount > maxRequestCount {
			_, _ = fmt.Fprintln(
				errorOutput,
				"request limit exceeded",
			)
			return 2
		}

		line := bytes.TrimSpace(scanner.Bytes())

		response := errorResponse("INVALID_JSON")
		if len(line) > 0 {
			response = processLine(line)
		}

		if err := encoder.Encode(response); err != nil {
			_, _ = fmt.Fprintln(
				errorOutput,
				"response encoding failed",
			)
			return 2
		}
	}

	if scanner.Err() != nil {
		_, _ = fmt.Fprintln(
			errorOutput,
			"input stream rejected",
		)
		return 2
	}

	return 0
}

func main() {
	os.Exit(
		run(
			os.Stdin,
			os.Stdout,
			os.Stderr,
		),
	)
}
