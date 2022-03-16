/*
Copyright 2021 The Flux authors

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

package chart

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/provenance"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/runtime/transform"

	"github.com/fluxcd/source-controller/internal/fs"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	"github.com/fluxcd/source-controller/internal/util"
)

type remoteChartBuilder struct {
	remote *repository.ChartRepository
}

// NewRemoteBuilder returns a Builder capable of building a Helm
// chart with a RemoteReference in the given repository.ChartRepository.
func NewRemoteBuilder(repository *repository.ChartRepository) Builder {
	return &remoteChartBuilder{
		remote: repository,
	}
}

// Build attempts to build a Helm chart with the given RemoteReference and
// BuildOptions, writing it to p.
// It returns a Build describing the produced (or from cache observed) chart
// written to p, or a BuildError.
//
// The latest version for the RemoteReference.Version is determined in the
// repository.ChartRepository, only downloading it if the version (including
// BuildOptions.VersionMetadata) differs from the current BuildOptions.CachedChart.
// BuildOptions.ValuesFiles changes are in this case not taken into account,
// and BuildOptions.Force should be used to enforce a rebuild.
//
// After downloading the chart, it is only packaged if required due to BuildOptions
// modifying the chart, otherwise the exact data as retrieved from the repository
// is written to p, after validating it to be a chart.
func (b *remoteChartBuilder) Build(_ context.Context, ref Reference, p string, opts BuildOptions) (*Build, error) {
	remoteRef, ok := ref.(RemoteReference)
	if !ok {
		err := fmt.Errorf("expected remote chart reference")
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	if err := ref.Validate(); err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	if err := b.remote.LoadFromCache(); err != nil {
		err = fmt.Errorf("could not load repository index for remote chart reference: %w", err)
		return nil, &BuildError{Reason: ErrChartPull, Err: err}
	}
	defer b.remote.Unload()

	// Get the current version for the RemoteReference
	cv, err := b.remote.Get(remoteRef.Name, remoteRef.Version)
	if err != nil {
		err = fmt.Errorf("failed to get chart version for remote reference: %w", err)
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	result := &Build{}
	result.Name = cv.Name
	result.Version = cv.Version

	// Set build specific metadata if instructed
	if opts.VersionMetadata != "" {
		ver, err := semver.NewVersion(result.Version)
		if err != nil {
			err = fmt.Errorf("failed to parse version from chart metadata as SemVer: %w", err)
			return nil, &BuildError{Reason: ErrChartMetadataPatch, Err: err}
		}
		if *ver, err = ver.SetMetadata(opts.VersionMetadata); err != nil {
			err = fmt.Errorf("failed to set SemVer metadata on chart version: %w", err)
			return nil, &BuildError{Reason: ErrChartMetadataPatch, Err: err}
		}
		result.Version = ver.String()
	}

	requiresPackaging := len(opts.GetValuesFiles()) != 0 || opts.VersionMetadata != ""

	verifyProvFile := func(chart, provFile string) (*provenance.Verification, error) {
		if opts.Keyring != nil {
			ver, err := verifyChartWithProvFile(bytes.NewReader(opts.Keyring), chart, provFile)
			if err != nil {
				err = fmt.Errorf("failed to verify helm chart using provenance file %s: %w", provFile, err)
				return nil, &BuildError{Reason: ErrProvenanceVerification, Err: err}
			}
			return ver, nil
		}
		return nil, nil
	}

	var provFilePath string

	// If all the following is true, we do not need to download and/or build the chart:
	// - Chart name from cached chart matches resolved name
	// - Chart version from cached chart matches calculated version
	// - BuildOptions.Force is False
	if opts.CachedChart != "" && !opts.Force {
		if curMeta, err := LoadChartMetadataFromArchive(opts.CachedChart); err == nil {
			// If the cached metadata is corrupt, we ignore its existence
			// and continue the build
			if err = curMeta.Validate(); err == nil {
				if result.Name == curMeta.Name && result.Version == curMeta.Version {
					// We can only verify a cached chart with provenance file if we didn't
					// package the chart ourselves, and instead stored it as is.
					if !requiresPackaging {
						provFilePath = provenanceFilePath(opts.CachedChart)
						ver, err := verifyProvFile(opts.CachedChart, provFilePath)
						if err != nil {
							return nil, err
						}
						if ver != nil {
							result.ProvFilePath = provFilePath
							result.VerificationSignature = buildVerificationSig(ver)
						}
					}
					result.Path = opts.CachedChart
					result.ValuesFiles = opts.GetValuesFiles()
					result.Packaged = requiresPackaging
					return result, nil
				}
			}
		}
	}

	// Download the package for the resolved version
	res, err := b.remote.DownloadChart(cv)
	if err != nil {
		err = fmt.Errorf("failed to download chart for remote reference: %w", err)
		return result, &BuildError{Reason: ErrChartPull, Err: err}
	}
	// Deal with the underlying byte slice to avoid having to read the buffer multiple times.
	chartBuf := res.Bytes()

	if opts.Keyring != nil {
		provFilePath = provenanceFilePath(p)
		err := b.remote.DownloadProvenanceFile(cv, provFilePath)
		if err != nil {
			err = fmt.Errorf("failed to download provenance file for remote reference: %w", err)
			return nil, &BuildError{Reason: ErrChartPull, Err: err}
		}
		// Write the remote chart temporarily to verify it with provenance file.
		// This is needed, since the verification will work only if the .tgz file is untampered.
		// But we write the packaged chart to disk under a different name, so the provenance file
		// will not be valid for this _new_ packaged chart.
		chart, err := util.WriteToFile(chartBuf, fmt.Sprintf("%s-%s.tgz", cv.Name, cv.Version))
		defer os.Remove(chart.Name())
		if err != nil {
			return nil, err
		}
		ver, err := verifyProvFile(chart.Name(), provFilePath)
		if err != nil {
			return nil, err
		}
		if ver != nil {
			result.ProvFilePath = provFilePath
			result.VerificationSignature = buildVerificationSig(ver)
		}
	}

	// Use literal chart copy from remote if no custom values files options are
	// set or version metadata isn't set.
	if !requiresPackaging {
		if err = validatePackageAndWriteToPath(chartBuf, p); err != nil {
			return nil, &BuildError{Reason: ErrChartPull, Err: err}
		}
		result.Path = p
		return result, nil
	}

	// Load the chart and merge chart values
	var chart *helmchart.Chart
	if chart, err = loader.LoadArchive(bytes.NewBuffer(chartBuf)); err != nil {
		err = fmt.Errorf("failed to load downloaded chart: %w", err)
		return result, &BuildError{Reason: ErrChartPackage, Err: err}
	}
	chart.Metadata.Version = result.Version

	mergedValues, err := mergeChartValues(chart, opts.ValuesFiles)
	if err != nil {
		err = fmt.Errorf("failed to merge chart values: %w", err)
		return result, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
	}
	// Overwrite default values with merged values, if any
	if ok, err = OverwriteChartDefaultValues(chart, mergedValues); ok || err != nil {
		if err != nil {
			return nil, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
		}
		result.ValuesFiles = opts.GetValuesFiles()
	}

	// Package the chart with the custom values
	if err = packageToPath(chart, p); err != nil {
		return nil, &BuildError{Reason: ErrChartPackage, Err: err}
	}

	result.Path = p
	result.Packaged = true
	return result, nil
}

// mergeChartValues merges the given chart.Chart Files paths into a single "values.yaml" map.
// It returns the merge result, or an error.
func mergeChartValues(chart *helmchart.Chart, paths []string) (map[string]interface{}, error) {
	mergedValues := make(map[string]interface{})
	for _, p := range paths {
		cfn := filepath.Clean(p)
		if cfn == chartutil.ValuesfileName {
			mergedValues = transform.MergeMaps(mergedValues, chart.Values)
			continue
		}
		var b []byte
		for _, f := range chart.Files {
			if f.Name == cfn {
				b = f.Data
				break
			}
		}
		if b == nil {
			return nil, fmt.Errorf("no values file found at path '%s'", p)
		}
		values := make(map[string]interface{})
		if err := yaml.Unmarshal(b, &values); err != nil {
			return nil, fmt.Errorf("unmarshaling values from '%s' failed: %w", p, err)
		}
		mergedValues = transform.MergeMaps(mergedValues, values)
	}
	return mergedValues, nil
}

// validatePackageAndWriteToPath atomically writes the packaged chart from reader
// to out while validating it by loading the chart metadata from the archive.
func validatePackageAndWriteToPath(b []byte, out string) error {
	tmpFile, err := util.WriteToTempFile(b, out)
	defer os.Remove(tmpFile.Name())

	if err != nil {
		return fmt.Errorf("failed to write packaged chart to temp file: %w", err)
	}
	meta, err := LoadChartMetadataFromArchive(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("failed to load chart metadata from written chart: %w", err)
	}
	if err = meta.Validate(); err != nil {
		return fmt.Errorf("failed to validate metadata of written chart: %w", err)
	}
	if err = fs.RenameWithFallback(tmpFile.Name(), out); err != nil {
		return fmt.Errorf("failed to write chart to file: %w", err)
	}
	return nil
}

// pathIsDir returns a boolean indicating if the given path points to a directory.
// In case os.Stat on the given path returns an error it returns false as well.
func pathIsDir(p string) bool {
	if p == "" {
		return false
	}
	if i, err := os.Stat(p); err != nil || !i.IsDir() {
		return false
	}
	return true
}
