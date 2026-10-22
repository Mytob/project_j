package containerhealth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
)

const maxManagedImages = 500
const maxHostContainers = 10000

var applicationImageReference = regexp.MustCompile(`^jellyfin-proxy/(admin|caddy|hostmetrics|security|wireguard):[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var dockerImageID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type imageSummary struct {
	ID       string            `json:"Id"`
	RepoTags []string          `json:"RepoTags"`
	Labels   map[string]string `json:"Labels"`
}

type imageContainerSummary struct {
	ImageID string `json:"ImageID"`
}

type ImageCleanupResult struct {
	RemovedImages int `json:"removed_images"`
	KeptImages    int `json:"kept_images"`
}

// RemoveUnusedApplicationImages deletes only old images built for the
// Jellyfin Proxy application. Exact references in the active and rollback
// releases are protected, as are images used by any container. It never uses
// prune or force, and is callable only by the host maintenance service/CLI;
// there is no HTTP route that accepts Docker image identifiers.
func (o *Observer) RemoveUnusedApplicationImages(ctx context.Context, protectedReferences []string) (ImageCleanupResult, error) {
	protected := make(map[string]struct{}, len(protectedReferences))
	for _, reference := range protectedReferences {
		if !applicationImageReference.MatchString(reference) {
			return ImageCleanupResult{}, errors.New("protected image reference is not a Jellyfin Proxy application image")
		}
		protected[reference] = struct{}{}
	}
	if len(protected) == 0 {
		return ImageCleanupResult{}, errors.New("active release image references are required before cleanup")
	}

	apiVersion, err := o.negotiateAPIVersion(ctx)
	if err != nil {
		return ImageCleanupResult{}, err
	}
	filters, _ := json.Marshal(map[string][]string{"label": {managedLabel}})
	query := url.Values{"all": {"1"}, "filters": {string(filters)}}
	var images []imageSummary
	if err := o.get(ctx, "/v"+apiVersion+"/images/json?"+query.Encode(), &images); err != nil {
		return ImageCleanupResult{}, fmt.Errorf("list managed application images: %w", err)
	}
	if len(images) > maxManagedImages {
		return ImageCleanupResult{}, errors.New("Docker returned too many managed application images")
	}
	var containers []imageContainerSummary
	if err := o.get(ctx, "/v"+apiVersion+"/containers/json?all=1", &containers); err != nil {
		return ImageCleanupResult{}, fmt.Errorf("list containers before image cleanup: %w", err)
	}
	if len(containers) > maxHostContainers {
		return ImageCleanupResult{}, errors.New("Docker returned too many containers for a safe image cleanup")
	}
	inUse := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		if container.ImageID != "" {
			inUse[container.ImageID] = struct{}{}
		}
	}

	candidates := make([]imageSummary, 0, len(images))
	kept := 0
	for _, image := range images {
		if image.Labels["jellyfin.proxy.role"] != "application" {
			continue
		}
		if !dockerImageID.MatchString(image.ID) || len(image.RepoTags) == 0 || len(image.RepoTags) > 32 {
			kept++
			continue
		}
		allOwnedTags := true
		isProtected := false
		for _, tag := range image.RepoTags {
			if !applicationImageReference.MatchString(tag) {
				allOwnedTags = false
				break
			}
			if _, ok := protected[tag]; ok {
				isProtected = true
			}
		}
		if !allOwnedTags || isProtected {
			kept++
			continue
		}
		if _, used := inUse[image.ID]; used {
			kept++
			continue
		}
		candidates = append(candidates, image)
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	result := ImageCleanupResult{KeptImages: kept}
	for _, image := range candidates {
		request, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/v"+apiVersion+"/images/"+url.PathEscape(image.ID)+"?force=false&noprune=false", nil)
		if err != nil {
			return result, err
		}
		response, err := o.client.Do(request)
		if err != nil {
			return result, fmt.Errorf("remove unused application image %s: %w", image.ID, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return result, fmt.Errorf("remove unused application image returned status %d", response.StatusCode)
		}
		result.RemovedImages++
	}
	return result, nil
}
