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
	"fmt"
	"strings"

	"code.gitea.io/sdk/gitea"

	"github.com/konflux-ci/build-service/pkg/boerrors"
	gp "github.com/konflux-ci/build-service/pkg/git/gitprovider"
)

const (
	webhookContentType = "json"
)

var (
	// PaC webhook events required for Gitea
	appStudioPaCWebhookEvents = []string{"pull_request", "push", "issue_comment", "commit_comment"}
)

// Allow mocking for tests
var NewGiteaClient func(accessToken, baseUrl string) (*GiteaClient, error) = newGiteaClient
var NewGiteaClientWithBasicAuth func(username, password, baseUrl string) (*GiteaClient, error) = newGiteaClientWithBasicAuth

var _ gp.GitProviderClient = (*GiteaClient)(nil)

type GiteaClient struct {
	client *gitea.Client
}

// EnsurePaCMergeRequest creates or updates existing (if needed) Pipelines as Code configuration proposal merge request.
// Returns the merge request web URL.
// If there is no error and web URL is empty, it means that the merge request is not needed (main branch is up to date).
func (g *GiteaClient) EnsurePaCMergeRequest(repoUrl string, d *gp.MergeRequestData) (webUrl string, err error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return "", err
	}

	// Determine base branch
	if d.BaseBranchName == "" {
		baseBranch, err := g.getDefaultBranchWithChecks(owner, repository)
		if err != nil {
			return "", err
		}
		d.BaseBranchName = baseBranch
	} else {
		exists, err := g.branchExist(owner, repository, d.BaseBranchName)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", boerrors.NewBuildOpError(boerrors.EGiteaBranchDoesntExist, fmt.Errorf("base branch '%s' does not exist", d.BaseBranchName))
		}
	}

	// Check if files are already up to date in base branch
	filesUpToDate, err := g.filesUpToDate(owner, repository, d.BaseBranchName, d.Files)
	if err != nil {
		return "", err
	}
	if filesUpToDate {
		// Configuration is already in the base branch
		return "", nil
	}

	// Check if PR branch exists
	prBranchExists, err := g.branchExist(owner, repository, d.BranchName)
	if err != nil {
		return "", err
	}

	if prBranchExists {
		// Branch exists, check if files are up to date
		branchFilesUpToDate, err := g.filesUpToDate(owner, repository, d.BranchName, d.Files)
		if err != nil {
			return "", err
		}
		if !branchFilesUpToDate {
			// Update files in the branch
			err := g.commitFilesIntoBranch(owner, repository, d.BranchName, d.CommitMessage, d.AuthorName, d.AuthorEmail, d.SignedOff, d.Files)
			if err != nil {
				return "", err
			}
		}

		// Check if PR already exists
		pr, err := g.findPullRequestByBranches(owner, repository, d.BranchName, d.BaseBranchName)
		if err != nil {
			return "", err
		}
		if pr != nil {
			// PR already exists
			return pr.HTMLURL, nil
		}

		// Check if there's a diff between branches
		diffExists, err := g.diffNotEmpty(owner, repository, d.BranchName, d.BaseBranchName)
		if err != nil {
			return "", err
		}
		if !diffExists {
			// No diff - delete stale branch and recurse
			if _, err := g.deleteBranch(owner, repository, d.BranchName); err != nil {
				return "", err
			}
			return g.EnsurePaCMergeRequest(repoUrl, d)
		}

		// Create new PR
		return g.createPullRequestWithinRepository(owner, repository, d.BranchName, d.BaseBranchName, d.Title, d.Text)
	} else {
		// Branch doesn't exist - create it
		_, err = g.createBranch(owner, repository, d.BranchName, d.BaseBranchName)
		if err != nil {
			return "", err
		}

		// Commit files to the new branch
		err = g.commitFilesIntoBranch(owner, repository, d.BranchName, d.CommitMessage, d.AuthorName, d.AuthorEmail, d.SignedOff, d.Files)
		if err != nil {
			return "", err
		}

		// Create PR
		return g.createPullRequestWithinRepository(owner, repository, d.BranchName, d.BaseBranchName, d.Title, d.Text)
	}
}

// UndoPaCMergeRequest creates a merge request that removes Pipelines as Code configuration from the repository.
func (g *GiteaClient) UndoPaCMergeRequest(repoUrl string, d *gp.MergeRequestData) (webUrl string, err error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return "", err
	}

	// Determine base branch
	if d.BaseBranchName == "" {
		baseBranch, err := g.getDefaultBranchWithChecks(owner, repository)
		if err != nil {
			return "", err
		}
		d.BaseBranchName = baseBranch
	} else {
		exists, err := g.branchExist(owner, repository, d.BaseBranchName)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", boerrors.NewBuildOpError(boerrors.EGiteaBranchDoesntExist, fmt.Errorf("base branch '%s' does not exist", d.BaseBranchName))
		}
	}

	// Check if any files to delete exist in base branch
	hasFilesToDelete := false
	for _, file := range d.Files {
		exists, err := g.fileExist(owner, repository, d.BaseBranchName, file.FullPath)
		if err != nil {
			return "", err
		}
		if exists {
			hasFilesToDelete = true
			break
		}
	}

	if !hasFilesToDelete {
		// Nothing to delete, configuration already removed
		return "", nil
	}

	// Delete old branch if it exists
	branchExists, err := g.branchExist(owner, repository, d.BranchName)
	if err != nil {
		return "", err
	}
	if branchExists {
		if _, err := g.deleteBranch(owner, repository, d.BranchName); err != nil {
			return "", err
		}
	}

	// Create new branch
	_, err = g.createBranch(owner, repository, d.BranchName, d.BaseBranchName)
	if err != nil {
		return "", err
	}

	// Commit file deletions
	err = g.commitDeletesIntoBranch(owner, repository, d.BranchName, d.CommitMessage, d.AuthorName, d.AuthorEmail, d.SignedOff, d.Files)
	if err != nil {
		return "", err
	}

	// Create PR
	return g.createPullRequestWithinRepository(owner, repository, d.BranchName, d.BaseBranchName, d.Title, d.Text)
}

// FindUnmergedPaCMergeRequest finds an existing unmerged PaC configuration merge request.
func (g *GiteaClient) FindUnmergedPaCMergeRequest(repoUrl string, d *gp.MergeRequestData) (*gp.MergeRequest, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return nil, err
	}

	// Determine base branch if not specified
	baseBranch := d.BaseBranchName
	if baseBranch == "" {
		baseBranch, err = g.getDefaultBranchWithChecks(owner, repository)
		if err != nil {
			return nil, err
		}
	}

	// Find PR by branches
	pr, err := g.findPullRequestByBranches(owner, repository, d.BranchName, baseBranch)
	if err != nil {
		return nil, err
	}

	if pr == nil {
		return nil, nil
	}

	// Convert Gitea PR to MergeRequest
	return &gp.MergeRequest{
		Id:        pr.ID,
		CreatedAt: pr.Created,
		WebUrl:    pr.HTMLURL,
		Title:     pr.Title,
	}, nil
}

// SetupPaCWebhook creates a webhook for Pipelines as Code in the repository.
func (g *GiteaClient) SetupPaCWebhook(repoUrl string, webhookUrl string, webhookSecret string) error {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return err
	}

	// Check if webhook already exists
	existingWebhook, err := g.getWebhookByTargetUrl(owner, repository, webhookUrl)
	if err != nil {
		return err
	}

	insecureSSL := false
	if gp.IsInsecureSSL() {
		insecureSSL = true
	}

	if existingWebhook == nil {
		// Create new webhook
		hookOpt := &gitea.CreateHookOption{
			Type: "gitea",
			Config: map[string]string{
				"url":          webhookUrl,
				"content_type": webhookContentType,
				"secret":       webhookSecret,
			},
			Events:       appStudioPaCWebhookEvents,
			Active:       true,
			BranchFilter: "*",
		}

		if insecureSSL {
			hookOpt.Config["insecure_ssl"] = "1"
		} else {
			hookOpt.Config["insecure_ssl"] = "0"
		}

		_, err = g.createWebhook(owner, repository, hookOpt)
		return err
	}

	// Update existing webhook to ensure it has correct configuration
	updateOpt := &gitea.EditHookOption{
		Config: map[string]string{
			"url":          webhookUrl,
			"content_type": webhookContentType,
			"secret":       webhookSecret,
		},
		Events:       appStudioPaCWebhookEvents,
		Active:       gitea.OptionalBool(true),
		BranchFilter: "*",
	}

	if insecureSSL {
		updateOpt.Config["insecure_ssl"] = "1"
	} else {
		updateOpt.Config["insecure_ssl"] = "0"
	}

	_, err = g.updateWebhook(owner, repository, existingWebhook.ID, updateOpt)
	return err
}

// DeletePaCWebhook deletes the Pipelines as Code webhook from the repository.
func (g *GiteaClient) DeletePaCWebhook(repoUrl string, webhookUrl string) error {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return err
	}

	// Find webhook by URL
	existingWebhook, err := g.getWebhookByTargetUrl(owner, repository, webhookUrl)
	if err != nil {
		return err
	}

	if existingWebhook == nil {
		// Webhook doesn't exist, nothing to delete
		return nil
	}

	// Delete webhook
	return g.deleteWebhook(owner, repository, existingWebhook.ID)
}

// GetDefaultBranchWithChecks returns the default branch of the repository with additional checks.
func (g *GiteaClient) GetDefaultBranchWithChecks(repoUrl string) (string, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return "", err
	}

	return g.getDefaultBranchWithChecks(owner, repository)
}

// DeleteBranch deletes a branch from the repository.
func (g *GiteaClient) DeleteBranch(repoUrl string, branchName string) (bool, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return false, err
	}

	return g.deleteBranch(owner, repository, branchName)
}

// GetBranchSha returns the SHA of the latest commit on the specified branch.
func (g *GiteaClient) GetBranchSha(repoUrl string, branchName string) (string, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return "", err
	}

	branch, resp, err := g.getBranch(owner, repository, branchName)
	if err != nil {
		return "", refineGitHostingServiceError(resp.Response, err)
	}
	if branch == nil {
		return "", fmt.Errorf("branch '%s' not found", branchName)
	}

	return branch.Commit.ID, nil
}

// GetBrowseRepositoryAtShaLink returns a web URL to view the repository at a specific commit SHA.
func (g *GiteaClient) GetBrowseRepositoryAtShaLink(repoUrl string, sha string) string {
	// Gitea repository URL format: https://gitea.example.com/owner/repo/commit/sha
	baseUrl, err := GetBaseUrl(repoUrl)
	if err != nil {
		return ""
	}

	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return ""
	}

	baseUrl = strings.TrimSuffix(baseUrl, "/")
	return fmt.Sprintf("%s/%s/%s/commit/%s", baseUrl, owner, repository, sha)
}

// DownloadFileContent downloads the content of a file from the repository.
func (g *GiteaClient) DownloadFileContent(repoUrl, branchName, filePath string) ([]byte, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return nil, err
	}

	return g.downloadFileContent(owner, repository, branchName, filePath)
}

// IsFileExist checks if a file exists in the repository at the specified branch.
func (g *GiteaClient) IsFileExist(repoUrl, branchName, filePath string) (bool, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return false, err
	}

	return g.fileExist(owner, repository, branchName, filePath)
}

// IsRepositoryPublic checks if the repository is publicly accessible.
func (g *GiteaClient) IsRepositoryPublic(repoUrl string) (bool, error) {
	owner, repository, err := getOwnerAndRepoFromUrl(repoUrl)
	if err != nil {
		return false, err
	}

	return g.isRepositoryPublic(owner, repository)
}

// GetConfiguredGitAppName returns the configured Git App name.
// Gitea does not support GitHub-style Apps, so this returns an error.
func (g *GiteaClient) GetConfiguredGitAppName() (string, string, error) {
	return "", "", boerrors.NewBuildOpError(boerrors.EGiteaGitAppNotSupported,
		fmt.Errorf("Gitea does not support GitHub-style applications"))
}

// GetAppUserId returns the user ID of the configured Git App.
// Gitea does not support GitHub-style Apps, so this returns an error.
func (g *GiteaClient) GetAppUserId(userName string) (int64, error) {
	return 0, boerrors.NewBuildOpError(boerrors.EGiteaGitAppNotSupported,
		fmt.Errorf("Gitea does not support GitHub-style applications"))
}

// newGiteaClient creates a new Gitea client with token authentication
func newGiteaClient(accessToken, baseUrl string) (*GiteaClient, error) {
	client, err := gitea.NewClient(baseUrl, gitea.SetToken(accessToken))
	if err != nil {
		return nil, err
	}
	return &GiteaClient{client: client}, nil
}

// newGiteaClientWithBasicAuth creates a new Gitea client with basic authentication
func newGiteaClientWithBasicAuth(username, password, baseUrl string) (*GiteaClient, error) {
	client, err := gitea.NewClient(baseUrl, gitea.SetBasicAuth(username, password))
	if err != nil {
		return nil, err
	}
	return &GiteaClient{client: client}, nil
}
