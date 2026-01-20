/*
Copyright 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gitea

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"code.gitea.io/sdk/gitea"

	"github.com/konflux-ci/build-service/pkg/boerrors"
	gp "github.com/konflux-ci/build-service/pkg/git/gitprovider"
)

type FailedToParseUrlError struct {
	url string
	err string
}

func (e FailedToParseUrlError) Error() string {
	return fmt.Sprintf("Failed to parse url: %s, error: %s", e.url, e.err)
}

type MissingSchemaError struct {
	url string
}

func (e MissingSchemaError) Error() string {
	return fmt.Sprintf("Failed to detect schema in url %s", e.url)
}

type MissingHostError struct {
	url string
}

func (e MissingHostError) Error() string {
	return fmt.Sprintf("Failed to detect host in url %s", e.url)
}

// getOwnerAndRepoFromUrl extracts owner and repository name from repository URL.
// Example: https://gitea.example.com/owner/repository -> owner, repository
func getOwnerAndRepoFromUrl(repoUrl string) (owner string, repository string, err error) {
	parsedUrl, err := url.Parse(strings.TrimSuffix(repoUrl, ".git"))
	if err != nil {
		return "", "", err
	}

	pathParts := strings.Split(strings.TrimPrefix(parsedUrl.Path, "/"), "/")
	if len(pathParts) < 2 {
		return "", "", fmt.Errorf("invalid repository URL format: %s", repoUrl)
	}

	owner = pathParts[0]
	repository = pathParts[1]
	return owner, repository, nil
}

// GetBaseUrl extracts the base URL from repository URL.
// Example: https://gitea.example.com/owner/repository -> https://gitea.example.com/
func GetBaseUrl(repoUrl string) (string, error) {
	parsedUrl, err := url.Parse(repoUrl)
	if err != nil {
		return "", FailedToParseUrlError{url: repoUrl, err: err.Error()}
	}

	if parsedUrl.Scheme == "" {
		return "", MissingSchemaError{repoUrl}
	}

	if parsedUrl.Host == "" {
		return "", MissingHostError{repoUrl}
	}

	// The gitea client library expects the base url to have a trailing slash
	return fmt.Sprintf("%s://%s/", parsedUrl.Scheme, parsedUrl.Host), nil
}

// refineGitHostingServiceError generates expected permanent error from Gitea response.
// If no one is detected, the original error will be returned.
// refineGitHostingServiceError should be called just after every Gitea API call.
func refineGitHostingServiceError(response *http.Response, originErr error) error {
	// Gitea SDK APIs do not return a http.Response object if the error is not related to an HTTP request.
	if response == nil {
		return originErr
	}

	switch response.StatusCode {
	case http.StatusUnauthorized:
		return boerrors.NewBuildOpError(boerrors.EGiteaTokenUnauthorized, originErr)
	case http.StatusForbidden:
		return boerrors.NewBuildOpError(boerrors.EGiteaTokenInsufficientScope, originErr)
	case http.StatusNotFound:
		return boerrors.NewBuildOpError(boerrors.EGiteaRepositoryNotFound, originErr)
	default:
		return originErr
	}
}

func (g *GiteaClient) getBranch(owner, repository, branchName string) (*gitea.Branch, *gitea.Response, error) {
	branch, resp, err := g.client.GetRepoBranch(owner, repository, branchName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, resp, nil
		}
		return nil, resp, err
	}
	return branch, resp, nil
}

func (g *GiteaClient) branchExist(owner, repository, branchName string) (bool, error) {
	_, resp, err := g.client.GetRepoBranch(owner, repository, branchName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (g *GiteaClient) createBranch(owner, repository, branchName, baseBranchName string) (*gitea.Branch, error) {
	opts := gitea.CreateBranchOption{
		BranchName: branchName,
	}

	// Get the base branch to get the commit SHA
	baseBranch, resp, err := g.getBranch(owner, repository, baseBranchName)
	if err != nil {
		return nil, refineGitHostingServiceError(resp.Response, err)
	}
	if baseBranch == nil {
		return nil, fmt.Errorf("base branch '%s' not found", baseBranchName)
	}

	opts.OldBranchName = baseBranchName

	branch, resp, err := g.client.CreateBranch(owner, repository, opts)
	return branch, refineGitHostingServiceError(resp.Response, err)
}

func (g *GiteaClient) deleteBranch(owner, repository, branchName string) (bool, error) {
	deleted, resp, err := g.client.DeleteRepoBranch(owner, repository, branchName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			// The given branch doesn't exist
			return false, nil
		}
		return false, refineGitHostingServiceError(resp.Response, err)
	}
	return deleted, nil
}

func (g *GiteaClient) getDefaultBranch(owner, repository string) (string, error) {
	repo, resp, err := g.client.GetRepo(owner, repository)
	if err != nil {
		return "", refineGitHostingServiceError(resp.Response, err)
	}
	if repo == nil {
		return "", fmt.Errorf("repository info is empty in Gitea API response")
	}
	return repo.DefaultBranch, nil
}

// downloadFileContent retrieves requested file.
// filePath must be the full path to the file.
func (g *GiteaClient) downloadFileContent(owner, repository, branch, filePath string) ([]byte, error) {
	contents, resp, err := g.client.GetContents(owner, repository, branch, filePath)
	if err != nil {
		// Check if file not found
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, errors.New("not found")
		}
		return nil, refineGitHostingServiceError(resp.Response, err)
	}

	// Gitea returns file content in the Content field
	if contents == nil || contents.Content == nil {
		return nil, errors.New("not found")
	}

	return []byte(*contents.Content), nil
}

// filesUpToDate checks if all given files have expected content in remote git repository.
func (g *GiteaClient) filesUpToDate(owner, repository, branch string, files []gp.RepositoryFile) (bool, error) {
	for _, file := range files {
		remoteFileBytes, err := g.downloadFileContent(owner, repository, branch, file.FullPath)
		if err != nil {
			if err.Error() == "not found" {
				// File doesn't exist in the repository
				return false, nil
			}
			return false, err
		}

		if !bytes.Equal(file.Content, remoteFileBytes) {
			// File content differs
			return false, nil
		}
	}
	return true, nil
}

func (g *GiteaClient) getDefaultBranchWithChecks(owner, repository string) (string, error) {
	defaultBranch, err := g.getDefaultBranch(owner, repository)
	if err != nil {
		return "", err
	}

	// Verify the branch exists
	exists, err := g.branchExist(owner, repository, defaultBranch)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("default branch '%s' does not exist", defaultBranch)
	}

	return defaultBranch, nil
}

// fileExist checks if a file exists in the repository at the given branch
func (g *GiteaClient) fileExist(owner, repository, branch, filePath string) (bool, error) {
	_, resp, err := g.client.GetContents(owner, repository, branch, filePath)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, refineGitHostingServiceError(resp.Response, err)
	}
	return true, nil
}

// isRepositoryPublic checks if the repository is public
func (g *GiteaClient) isRepositoryPublic(owner, repository string) (bool, error) {
	repo, resp, err := g.client.GetRepo(owner, repository)
	if err != nil {
		return false, refineGitHostingServiceError(resp.Response, err)
	}
	if repo == nil {
		return false, fmt.Errorf("repository info is empty in Gitea API response")
	}
	return !repo.Private, nil
}

// commitFilesIntoBranch creates a commit with the given files in the specified branch
func (g *GiteaClient) commitFilesIntoBranch(owner, repository, branchName, commitMessage, authorName, authorEmail string, signedOff bool, files []gp.RepositoryFile) error {
	// Note: Gitea API doesn't support multi-file commits in a single operation
	// Each file needs to be created/updated individually
	for _, file := range files {
		// Check if file exists to determine if we should create or update
		exists, err := g.fileExist(owner, repository, branchName, file.FullPath)
		if err != nil {
			return err
		}

		author := gitea.Identity{
			Name:  authorName,
			Email: authorEmail,
		}

		if exists {
			// Update existing file
			opts := gitea.UpdateFileOptions{
				FileOptions: gitea.FileOptions{
					Message:    commitMessage,
					BranchName: branchName,
					Author:     author,
					Committer:  author,
					Signoff:    signedOff,
				},
				Content: base64Encode(file.Content),
			}
			_, resp, err := g.client.UpdateFile(owner, repository, file.FullPath, opts)
			if err != nil {
				return refineGitHostingServiceError(resp.Response, err)
			}
		} else {
			// Create new file
			opts := gitea.CreateFileOptions{
				FileOptions: gitea.FileOptions{
					Message:    commitMessage,
					BranchName: branchName,
					Author:     author,
					Committer:  author,
					Signoff:    signedOff,
				},
				Content: base64Encode(file.Content),
			}
			_, resp, err := g.client.CreateFile(owner, repository, file.FullPath, opts)
			if err != nil {
				return refineGitHostingServiceError(resp.Response, err)
			}
		}
	}

	return nil
}

// commitDeletesIntoBranch creates a commit that deletes the given files from the specified branch
func (g *GiteaClient) commitDeletesIntoBranch(owner, repository, branchName, commitMessage, authorName, authorEmail string, signedOff bool, files []gp.RepositoryFile) error {
	// Delete each file individually
	for _, file := range files {
		author := gitea.Identity{
			Name:  authorName,
			Email: authorEmail,
		}

		opts := gitea.DeleteFileOptions{
			FileOptions: gitea.FileOptions{
				Message:    commitMessage,
				BranchName: branchName,
				Author:     author,
				Committer:  author,
				Signoff:    signedOff,
			},
		}

		resp, err := g.client.DeleteFile(owner, repository, file.FullPath, opts)
		if err != nil {
			// Ignore error if file doesn't exist
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				continue
			}
			return refineGitHostingServiceError(resp.Response, err)
		}
	}

	return nil
}

// findPullRequestByBranches searches for a PR within repository by head and base branches
func (g *GiteaClient) findPullRequestByBranches(owner, repository, headBranch, baseBranch string) (*gitea.PullRequest, error) {
	opts := gitea.ListPullRequestsOptions{
		State: gitea.StateOpen,
		ListOptions: gitea.ListOptions{
			Page:     1,
			PageSize: 100,
		},
	}

	prs, resp, err := g.client.ListRepoPullRequests(owner, repository, opts)
	if err != nil {
		return nil, refineGitHostingServiceError(resp.Response, err)
	}

	// Filter by head and base branches
	var matchingPRs []*gitea.PullRequest
	for _, pr := range prs {
		if pr.Head != nil && pr.Base != nil {
			if pr.Head.Ref == headBranch && pr.Base.Ref == baseBranch {
				matchingPRs = append(matchingPRs, pr)
			}
		}
	}

	switch len(matchingPRs) {
	case 0:
		return nil, nil
	case 1:
		return matchingPRs[0], nil
	default:
		return nil, fmt.Errorf("found %d pull requests for head=%s base=%s, expected 0 or 1", len(matchingPRs), headBranch, baseBranch)
	}
}

// createPullRequestWithinRepository creates a new pull request in the repository
func (g *GiteaClient) createPullRequestWithinRepository(owner, repository, headBranch, baseBranch, title, body string) (string, error) {
	opts := gitea.CreatePullRequestOption{
		Head:  headBranch,
		Base:  baseBranch,
		Title: title,
		Body:  body,
	}

	pr, resp, err := g.client.CreatePullRequest(owner, repository, opts)
	if err != nil {
		return "", refineGitHostingServiceError(resp.Response, err)
	}

	return pr.HTMLURL, nil
}

// diffNotEmpty checks if there are differences between two branches
func (g *GiteaClient) diffNotEmpty(owner, repository, headBranch, baseBranch string) (bool, error) {
	// Get branch info for both branches
	headBranchInfo, resp, err := g.client.GetRepoBranch(owner, repository, headBranch)
	if err != nil {
		return false, refineGitHostingServiceError(resp.Response, err)
	}

	baseBranchInfo, resp, err := g.client.GetRepoBranch(owner, repository, baseBranch)
	if err != nil {
		return false, refineGitHostingServiceError(resp.Response, err)
	}

	// If the commit SHAs are the same, there's no diff
	if headBranchInfo.Commit != nil && baseBranchInfo.Commit != nil {
		if headBranchInfo.Commit.ID == baseBranchInfo.Commit.ID {
			return false, nil
		}
	}

	// Otherwise there is a diff
	return true, nil
}

// getWebhookByTargetUrl returns webhook by its target URL or nil if it doesn't exist
func (g *GiteaClient) getWebhookByTargetUrl(owner, repository, webhookTargetUrl string) (*gitea.Hook, error) {
	opts := gitea.ListHooksOptions{
		ListOptions: gitea.ListOptions{
			Page:     1,
			PageSize: 100,
		},
	}

	webhooks, resp, err := g.client.ListRepoHooks(owner, repository, opts)
	if err != nil {
		return nil, refineGitHostingServiceError(resp.Response, err)
	}

	for _, webhook := range webhooks {
		if webhook.Config["url"] == webhookTargetUrl {
			return webhook, nil
		}
	}

	return nil, nil
}

// createWebhook creates a new webhook in the repository
func (g *GiteaClient) createWebhook(owner, repository string, hook *gitea.CreateHookOption) (*gitea.Hook, error) {
	webhook, resp, err := g.client.CreateRepoHook(owner, repository, *hook)
	return webhook, refineGitHostingServiceError(resp.Response, err)
}

// updateWebhook updates an existing webhook
func (g *GiteaClient) updateWebhook(owner, repository string, webhookID int64, hook *gitea.EditHookOption) (*gitea.Hook, error) {
	resp, err := g.client.EditRepoHook(owner, repository, webhookID, *hook)
	return nil, refineGitHostingServiceError(resp.Response, err)
}

// deleteWebhook deletes a webhook
func (g *GiteaClient) deleteWebhook(owner, repository string, webhookID int64) error {
	resp, err := g.client.DeleteRepoHook(owner, repository, webhookID)
	return refineGitHostingServiceError(resp.Response, err)
}

// base64Encode encodes a byte slice to base64 string as required by Gitea API
func base64Encode(content []byte) string {
	return base64.StdEncoding.EncodeToString(content)
}
