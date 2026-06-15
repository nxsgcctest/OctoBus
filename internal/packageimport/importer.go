package packageimport

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"octobus/internal/descriptors"
	"octobus/internal/domain"
	"octobus/internal/store"
)

type Importer struct {
	DataDir string
	Store   *store.Store
}

type Options struct {
	ServiceID string `json:"service_id"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Offline   bool   `json:"offline"`
	Reinstall bool   `json:"reinstall"`
	Build     string `json:"build"`
	Recursive bool   `json:"recursive"`
}

type Result struct {
	Service  domain.Service
	Manifest domain.ServiceManifest
}

type RecursiveResult struct {
	Services           []domain.Service
	ServiceCount       int
	Manifests          map[string]domain.ServiceManifest
	RestartedInstances map[string][]string
	RestartErrors      map[string][]string
}

type preparedSource struct {
	ArtifactPath          string
	PackageDir            string
	PackageSHA256         string
	PackageSource         string
	PackageVersion        string
	ServiceRoot           string
	BuildAllowed          bool
	RuntimeNodeModulesDir string
}

type BuildPolicy string

const (
	BuildAuto   BuildPolicy = "auto"
	BuildAlways BuildPolicy = "always"
	BuildNever  BuildPolicy = "never"
)

func (i *Importer) Import(ctx context.Context, opts Options) (Result, error) {
	if i.Store == nil {
		return Result{}, errors.New("store is required")
	}
	if err := domain.ValidateID("service", opts.ServiceID); err != nil {
		return Result{}, err
	}
	if opts.Source == "" {
		return Result{}, errors.New("service package source is required")
	}
	serviceDir := filepath.Join(i.DataDir, "artifacts", "services", opts.ServiceID)
	staging := filepath.Join(i.DataDir, "artifacts", "services", ".staging-"+opts.ServiceID)
	if err := os.RemoveAll(staging); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(staging)

	prepared, err := i.prepareSource(ctx, opts, staging)
	if err != nil {
		return Result{}, err
	}
	policy, err := parseBuildPolicy(opts.Build)
	if err != nil {
		return Result{}, err
	}
	if prepared, err = buildSourcePackage(ctx, prepared, staging, policy, opts.Offline); err != nil {
		return Result{}, err
	}
	serviceRootDir := filepath.Join(prepared.PackageDir, filepath.FromSlash(prepared.ServiceRoot))
	manifest, err := readManifest(serviceRootDir)
	if err != nil {
		return Result{}, err
	}
	entry, err := inferPackageBinForService(prepared.PackageDir, manifest.Name)
	if err != nil {
		return Result{}, err
	}
	if err := validatePackageFile(prepared.PackageDir, entry, "package.json bin"); err != nil {
		return Result{}, err
	}
	runtimeMode, err := domain.ManifestRuntimeMode(manifest)
	if err != nil {
		return Result{}, err
	}
	runtimeDir := filepath.Join(staging, "runtime")
	if err := copyDir(prepared.PackageDir, runtimeDir); err != nil {
		return Result{}, err
	}
	if prepared.RuntimeNodeModulesDir != "" {
		if err := copyDir(prepared.RuntimeNodeModulesDir, filepath.Join(runtimeDir, "node_modules")); err != nil {
			return Result{}, err
		}
	}
	if err := replaceLocalExampleSDK(runtimeDir); err != nil {
		return Result{}, err
	}
	if err := prepareRuntime(ctx, runtimeDir, opts.Offline, opts.Reinstall); err != nil {
		return Result{}, err
	}
	if err := replaceLocalExampleSDK(runtimeDir); err != nil {
		return Result{}, err
	}
	descriptorPath := filepath.Join(staging, "descriptor.protoset")
	compiled, err := descriptors.Compile(descriptors.CompileRequest{
		PackageDir:     serviceRootDir,
		ProtoRoots:     manifest.Proto.Roots,
		ProtoFiles:     manifest.Proto.Files,
		DescriptorPath: descriptorPath,
	})
	if err != nil {
		return Result{}, err
	}
	commitDir := filepath.Join(staging, "service")
	finalPackageDir := filepath.Join(commitDir, "package")
	finalRuntimeDir := filepath.Join(commitDir, "runtime")
	finalDescriptor := filepath.Join(commitDir, "descriptor.protoset")
	finalArtifact := filepath.Join(commitDir, filepath.Base(prepared.ArtifactPath))
	if err := os.RemoveAll(commitDir); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(commitDir, 0o755); err != nil {
		return Result{}, err
	}
	if err := copyFile(prepared.ArtifactPath, finalArtifact, 0o644); err != nil {
		return Result{}, err
	}
	if err := copyDir(prepared.PackageDir, finalPackageDir); err != nil {
		return Result{}, err
	}
	if err := copyDir(runtimeDir, finalRuntimeDir); err != nil {
		return Result{}, err
	}
	if err := copyFile(descriptorPath, finalDescriptor, 0o644); err != nil {
		return Result{}, err
	}

	serviceName, err := i.importServiceName(ctx, opts, manifest)
	if err != nil {
		return Result{}, err
	}
	configSchemaPath := ""
	if manifest.ConfigSchema != "" {
		if err := validatePackageFile(filepath.Join(finalPackageDir, filepath.FromSlash(prepared.ServiceRoot)), manifest.ConfigSchema, "configSchema"); err != nil {
			return Result{}, err
		}
		configSchemaPath = filepath.Join(serviceDir, "package", filepath.FromSlash(prepared.ServiceRoot), manifest.ConfigSchema)
	}
	secretSchemaPath := ""
	if manifest.SecretSchema != "" {
		if err := validatePackageFile(filepath.Join(finalPackageDir, filepath.FromSlash(prepared.ServiceRoot)), manifest.SecretSchema, "secretSchema"); err != nil {
			return Result{}, err
		}
		secretSchemaPath = filepath.Join(serviceDir, "package", filepath.FromSlash(prepared.ServiceRoot), manifest.SecretSchema)
	}
	finalStoredArtifact := filepath.Join(serviceDir, filepath.Base(prepared.ArtifactPath))
	finalStoredDescriptor := filepath.Join(serviceDir, "descriptor.protoset")
	svc := domain.Service{
		ID:                  opts.ServiceID,
		Name:                serviceName,
		PackageSource:       prepared.PackageSource,
		PackageArtifactPath: finalStoredArtifact,
		PackageSHA256:       prepared.PackageSHA256,
		PackageVersion:      prepared.PackageVersion,
		DescriptorPath:      finalStoredDescriptor,
		DescriptorSHA256:    compiled.DescriptorSHA256,
		DescriptorVersion:   compiled.DescriptorVersion,
		Methods:             compiled.Methods,
		NodeEntry:           entry,
		ServiceRoot:         prepared.ServiceRoot,
		RuntimeMode:         runtimeMode,
		ConfigSchemaPath:    configSchemaPath,
		SecretSchemaPath:    secretSchemaPath,
	}
	rollback, cleanup, err := replaceServiceDir(serviceDir, commitDir)
	if err != nil {
		return Result{}, err
	}
	if err := i.Store.UpsertService(ctx, svc); err != nil {
		_ = rollback()
		return Result{}, err
	}
	if err := cleanup(); err != nil {
		return Result{}, err
	}
	stored, err := i.Store.GetService(ctx, opts.ServiceID)
	if err != nil {
		return Result{}, err
	}
	return Result{Service: stored, Manifest: manifest}, nil
}

func (i *Importer) ImportRecursive(ctx context.Context, opts Options) (RecursiveResult, error) {
	if i.Store == nil {
		return RecursiveResult{}, errors.New("store is required")
	}
	if opts.Source == "" {
		return RecursiveResult{}, errors.New("service package source is required")
	}
	if opts.ServiceID != "" {
		return RecursiveResult{}, errors.New("service_id cannot be used with recursive import")
	}
	if opts.Name != "" {
		return RecursiveResult{}, errors.New("name cannot be used with recursive import")
	}
	return RecursiveResult{}, errors.New("recursive import is not implemented")
}

func replaceLocalExampleSDK(runtimeDir string) error {
	raw, err := os.ReadFile(filepath.Join(runtimeDir, "package.json"))
	if err != nil {
		return err
	}
	var pkg struct {
		Name         string            `json:"name"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return err
	}
	if !localExamplePackageNames[pkg.Name] {
		return nil
	}
	if _, ok := pkg.Dependencies["@chaitin-ai/octobus-sdk"]; !ok {
		return nil
	}
	repoRoot, err := findRepoRootForLocalSDK(runtimeDir)
	if err != nil {
		return err
	}
	sdkDir := filepath.Join(repoRoot, "sdk")
	sdkCLI := filepath.Join(sdkDir, "dist", "cli.js")
	if _, err := os.Stat(sdkCLI); err != nil {
		return fmt.Errorf("local SDK build output missing at %s; run task sdk:build before importing local examples: %w", sdkCLI, err)
	}
	target := filepath.Join(runtimeDir, "node_modules", "@chaitin-ai", "octobus-sdk")
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return copyDir(sdkDir, target)
}

var localExamplePackageNames = map[string]bool{
	"octobus-calculator-js":           true,
	"octobus-calculator-on-demand-js": true,
	"octobus-streaming-js":            true,
}

func findRepoRootForLocalSDK(start string) (string, error) {
	if cwd, err := os.Getwd(); err == nil {
		if root, err := findRepoRootFrom(cwd); err == nil {
			return root, nil
		}
	}
	return findRepoRootFrom(start)
}

func findRepoRootFrom(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "sdk", "package.json")); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repo root with sdk package not found")
		}
		dir = parent
	}
}

func (i *Importer) importServiceName(ctx context.Context, opts Options, manifest domain.ServiceManifest) (string, error) {
	if opts.Name != "" {
		return opts.Name, nil
	}
	existing, err := i.Store.GetService(ctx, opts.ServiceID)
	if err == nil {
		return existing.Name, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if manifest.DisplayName != "" {
		return manifest.DisplayName, nil
	}
	return manifest.Name, nil
}

func (i *Importer) prepareSource(ctx context.Context, opts Options, staging string) (preparedSource, error) {
	source, serviceRoot, err := splitSourceServiceRoot(opts.Source)
	if err != nil {
		return preparedSource{}, err
	}
	switch classifySource(opts.Source) {
	case sourceNPM:
		prepared, err := i.packNPM(ctx, strings.TrimPrefix(source, "npm:"), staging)
		if err != nil {
			return preparedSource{}, err
		}
		prepared.PackageSource = sourceWithServiceRoot(prepared.PackageSource, serviceRoot)
		prepared.ServiceRoot = serviceRoot
		return prepared, nil
	case sourceHTTPSGit:
		return i.prepareGitSource(ctx, opts.Source, staging)
	case sourceUnsupportedGit:
		_, err := parseGitSource(opts.Source)
		if err != nil {
			return preparedSource{}, err
		}
		return preparedSource{}, fmt.Errorf("unsupported Git source %q", opts.Source)
	}
	info, err := os.Stat(source)
	if err != nil {
		return preparedSource{}, err
	}
	var artifactPath, packageDir string
	if info.IsDir() {
		artifactPath = filepath.Join(staging, "package.tgz")
		if err := tarGzDir(source, artifactPath); err != nil {
			return preparedSource{}, err
		}
		packageDir = filepath.Join(staging, "package")
		if err := copyDir(source, packageDir); err != nil {
			return preparedSource{}, err
		}
	} else {
		ext := strings.ToLower(filepath.Ext(source))
		name := "package" + ext
		if strings.HasSuffix(strings.ToLower(source), ".tgz") || strings.HasSuffix(strings.ToLower(source), ".tar.gz") {
			name = "package.tgz"
		}
		artifactPath = filepath.Join(staging, name)
		if err := copyFile(source, artifactPath, 0o644); err != nil {
			return preparedSource{}, err
		}
		packageDir = filepath.Join(staging, "package")
		if strings.HasSuffix(name, ".zip") {
			err = unzip(artifactPath, packageDir)
		} else {
			err = untarGz(artifactPath, packageDir)
		}
		if err != nil {
			return preparedSource{}, err
		}
		packageDir = normalizePackageDir(packageDir)
	}
	b, err := os.ReadFile(artifactPath)
	if err != nil {
		return preparedSource{}, err
	}
	return preparedSource{ArtifactPath: artifactPath, PackageDir: packageDir, PackageSHA256: domain.HashBytes(b), PackageSource: sourceWithServiceRoot(source, serviceRoot), ServiceRoot: serviceRoot, BuildAllowed: info.IsDir()}, nil
}

func splitSourceServiceRoot(raw string) (string, string, error) {
	if strings.Contains(raw, "://") {
		return raw, ".", nil
	}
	source, serviceRoot, ok := strings.Cut(raw, "//")
	if !ok {
		return raw, ".", nil
	}
	clean, err := cleanServiceRoot(serviceRoot)
	if err != nil {
		return "", "", err
	}
	if source == "" {
		return "", "", errors.New("service package source is required")
	}
	return source, clean, nil
}

func cleanServiceRoot(serviceRoot string) (string, error) {
	if err := domain.ValidatePackageRelativePath("service dir", serviceRoot); err != nil {
		return "", err
	}
	for _, part := range strings.Split(filepath.ToSlash(serviceRoot), "/") {
		if part == ".." {
			return "", errors.New("service dir must not contain ..")
		}
	}
	return filepath.ToSlash(filepath.Clean(serviceRoot)), nil
}

func sourceWithServiceRoot(source, serviceRoot string) string {
	if serviceRoot == "" || serviceRoot == "." {
		return source
	}
	return source + "//" + serviceRoot
}

func discoverServiceRoots(packageDir, scanRoot string) ([]string, error) {
	if scanRoot == "" {
		scanRoot = "."
	}
	cleanRoot := "."
	if scanRoot != "." {
		var err error
		cleanRoot, err = cleanServiceRoot(scanRoot)
		if err != nil {
			return nil, err
		}
	}
	scanDir := packageDir
	if cleanRoot != "." {
		scanDir = filepath.Join(packageDir, filepath.FromSlash(cleanRoot))
	}
	info, err := os.Stat(scanDir)
	if err != nil {
		return nil, fmt.Errorf("scan root %q: %w", cleanRoot, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan root %q is not a directory", cleanRoot)
	}
	var roots []string
	if err := filepath.WalkDir(scanDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		if path != scanDir && skipDiscoveryDir(entry.Name()) {
			return filepath.SkipDir
		}
		if _, err := os.Stat(filepath.Join(path, "service.json")); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(packageDir, path)
		if err != nil {
			return err
		}
		roots = append(roots, filepath.ToSlash(rel))
		return filepath.SkipDir
	}); err != nil {
		return nil, fmt.Errorf("discover service roots under %q: %w", cleanRoot, err)
	}
	sort.Strings(roots)
	if len(roots) == 0 {
		return nil, fmt.Errorf("no service roots found under %q", cleanRoot)
	}
	return roots, nil
}

func skipDiscoveryDir(name string) bool {
	return name == "node_modules" || name == ".git" || strings.HasPrefix(name, ".")
}

func (i *Importer) packNPM(ctx context.Context, spec, staging string) (preparedSource, error) {
	cmd := exec.CommandContext(ctx, "npm", "pack", spec, "--pack-destination", staging)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return preparedSource{}, fmt.Errorf("npm pack %s: %w: %s", spec, err, strings.TrimSpace(out.String()))
	}
	packed := strings.TrimSpace(out.String())
	if idx := strings.LastIndex(packed, "\n"); idx >= 0 {
		packed = strings.TrimSpace(packed[idx+1:])
	}
	artifactPath := filepath.Join(staging, filepath.Base(packed))
	packageDir := filepath.Join(staging, "package")
	if err := untarGz(artifactPath, packageDir); err != nil {
		return preparedSource{}, err
	}
	packageDir = normalizePackageDir(packageDir)
	b, err := os.ReadFile(artifactPath)
	if err != nil {
		return preparedSource{}, err
	}
	return preparedSource{ArtifactPath: artifactPath, PackageDir: packageDir, PackageSHA256: domain.HashBytes(b), PackageSource: "npm:" + spec, ServiceRoot: "."}, nil
}

func parseBuildPolicy(raw string) (BuildPolicy, error) {
	if raw == "" {
		return BuildAuto, nil
	}
	switch BuildPolicy(raw) {
	case BuildAuto, BuildAlways, BuildNever:
		return BuildPolicy(raw), nil
	default:
		return "", fmt.Errorf("invalid build policy %q: must be auto, always, or never", raw)
	}
}

func readManifest(packageDir string) (domain.ServiceManifest, error) {
	b, err := os.ReadFile(filepath.Join(packageDir, "service.json"))
	if err != nil {
		return domain.ServiceManifest{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return domain.ServiceManifest{}, err
	}
	if _, ok := raw["id"]; ok {
		return domain.ServiceManifest{}, errors.New("service manifest must not define id; pass the service id as service import SERVICE SOURCE")
	}
	var manifest domain.ServiceManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return domain.ServiceManifest{}, err
	}
	if err := domain.ValidateManifest(manifest); err != nil {
		return domain.ServiceManifest{}, err
	}
	return manifest, nil
}

func buildSourcePackage(ctx context.Context, prepared preparedSource, staging string, policy BuildPolicy, offline bool) (preparedSource, error) {
	if !prepared.BuildAllowed {
		if policy == BuildAlways && !prepared.BuildAllowed {
			return preparedSource{}, errors.New("--build=always is only supported for local directory and HTTPS Git sources")
		}
		return prepared, nil
	}
	entries, entryErr := parsePackageBinTargets(prepared.PackageDir)
	if entryErr != nil {
		return preparedSource{}, entryErr
	}
	entryExists := packageBinTargetsExist(prepared.PackageDir, entries)
	if policy == BuildNever {
		if !entryExists {
			return preparedSource{}, errors.New("package.json bin target does not exist")
		}
		if err := prepareSourceRuntimeDependencies(ctx, prepared.PackageDir, offline); err != nil {
			return preparedSource{}, err
		}
		prepared.RuntimeNodeModulesDir = existingNodeModulesDir(prepared.PackageDir)
		return packExistingPackage(ctx, prepared, staging)
	}
	scripts, err := readPackageScripts(prepared.PackageDir)
	if err != nil {
		return preparedSource{}, err
	}
	buildKind := selectBuildScript(scripts)
	if policy == BuildAuto && entryExists {
		if err := prepareSourceRuntimeDependencies(ctx, prepared.PackageDir, offline); err != nil {
			return preparedSource{}, err
		}
		prepared.RuntimeNodeModulesDir = existingNodeModulesDir(prepared.PackageDir)
		return packExistingPackage(ctx, prepared, staging)
	}
	if buildKind == "" {
		if policy == BuildAlways {
			return preparedSource{}, errors.New("--build=always requires package.json scripts.prepack, scripts.prepare, or scripts.build")
		}
		if len(entries) == 1 && !entryExists {
			return preparedSource{}, errors.New("package.json bin target does not exist and no build script is available")
		}
		return packExistingPackage(ctx, prepared, staging)
	}
	buildDir := filepath.Join(staging, "build")
	if err := os.RemoveAll(buildDir); err != nil {
		return preparedSource{}, err
	}
	if err := copyDir(prepared.PackageDir, buildDir); err != nil {
		return preparedSource{}, err
	}
	if err := npmInstall(ctx, buildDir, offline, false); err != nil {
		return preparedSource{}, err
	}
	if buildKind == "build" {
		if err := runNPM(ctx, buildDir, []string{"run", "build"}); err != nil {
			return preparedSource{}, err
		}
	}
	packed, err := npmPack(ctx, buildDir, filepath.Join(staging, "packed"))
	if err != nil {
		return preparedSource{}, err
	}
	packageDir := filepath.Join(staging, "built-package")
	if err := os.RemoveAll(packageDir); err != nil {
		return preparedSource{}, err
	}
	if err := untarGz(packed, packageDir); err != nil {
		return preparedSource{}, err
	}
	packageDir = normalizePackageDir(packageDir)
	b, err := os.ReadFile(packed)
	if err != nil {
		return preparedSource{}, err
	}
	prepared.ArtifactPath = packed
	prepared.PackageDir = packageDir
	prepared.PackageSHA256 = domain.HashBytes(b)
	prepared.RuntimeNodeModulesDir = existingNodeModulesDir(buildDir)
	return prepared, nil
}

func prepareSourceRuntimeDependencies(ctx context.Context, packageDir string, offline bool) error {
	if !hasLocalFileDependency(packageDir) {
		return nil
	}
	return npmInstall(ctx, packageDir, offline, true)
}

func hasLocalFileDependency(packageDir string) bool {
	deps, err := packageDependencies(packageDir)
	if err != nil {
		return false
	}
	for _, spec := range deps {
		if strings.HasPrefix(spec, "file:") {
			return true
		}
	}
	return false
}

func existingNodeModulesDir(packageDir string) string {
	dir := filepath.Join(packageDir, "node_modules")
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}

func packExistingPackage(ctx context.Context, prepared preparedSource, staging string) (preparedSource, error) {
	packed, err := npmPack(ctx, prepared.PackageDir, filepath.Join(staging, "packed"))
	if err != nil {
		return preparedSource{}, err
	}
	packageDir := filepath.Join(staging, "packed-package")
	if err := os.RemoveAll(packageDir); err != nil {
		return preparedSource{}, err
	}
	if err := untarGz(packed, packageDir); err != nil {
		return preparedSource{}, err
	}
	packageDir = normalizePackageDir(packageDir)
	b, err := os.ReadFile(packed)
	if err != nil {
		return preparedSource{}, err
	}
	prepared.ArtifactPath = packed
	prepared.PackageDir = packageDir
	prepared.PackageSHA256 = domain.HashBytes(b)
	return prepared, nil
}

func readPackageScripts(packageDir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(packageDir, "package.json"))
	if err != nil {
		return nil, errors.New("package.json cannot be read")
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, err
	}
	return pkg.Scripts, nil
}

func selectBuildScript(scripts map[string]string) string {
	for _, name := range []string{"prepack", "prepare", "build"} {
		if scripts[name] != "" {
			return name
		}
	}
	return ""
}

func inferPackageBin(packageDir string) (string, error) {
	return inferPackageBinForService(packageDir, "")
}

func inferPackageBinForService(packageDir, serviceName string) (string, error) {
	if serviceName != "" {
		entry, err := parsePackageBinForService(packageDir, serviceName)
		if err != nil {
			return "", err
		}
		if err := validatePackageFile(packageDir, entry, "package.json bin"); err != nil {
			return "", err
		}
		return entry, nil
	}
	entry, err := parsePackageBin(packageDir)
	if err != nil {
		return "", err
	}
	if err := validatePackageFile(packageDir, entry, "package.json bin"); err != nil {
		return "", err
	}
	return entry, nil
}

func parsePackageBin(packageDir string) (string, error) {
	return parsePackageBinForService(packageDir, "")
}

func parsePackageBinTargets(packageDir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(packageDir, "package.json"))
	if err != nil {
		return nil, errors.New("package.json cannot be read")
	}
	var pkg struct {
		Bin any `json:"bin"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, err
	}
	switch bin := pkg.Bin.(type) {
	case string:
		if err := domain.ValidatePackageRelativePath("package.json bin", bin); err != nil {
			return nil, err
		}
		return []string{filepath.Clean(bin)}, nil
	case map[string]any:
		if len(bin) == 0 {
			return nil, errors.New("package.json bin is required")
		}
		entries := make([]string, 0, len(bin))
		for name, value := range bin {
			target, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("package.json bin %q target must be a string", name)
			}
			if err := domain.ValidatePackageRelativePath("package.json bin", target); err != nil {
				return nil, err
			}
			entries = append(entries, filepath.Clean(target))
		}
		return entries, nil
	}
	return nil, errors.New("package.json bin is required")
}

func packageBinTargetsExist(packageDir string, entries []string) bool {
	for _, entry := range entries {
		if err := validatePackageFile(packageDir, entry, "package.json bin"); err != nil {
			return false
		}
	}
	return true
}

func parsePackageBinForService(packageDir, serviceName string) (string, error) {
	b, err := os.ReadFile(filepath.Join(packageDir, "package.json"))
	if err != nil {
		return "", errors.New("package.json cannot be read")
	}
	var pkg struct {
		Bin any `json:"bin"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return "", err
	}
	switch bin := pkg.Bin.(type) {
	case string:
		if err := domain.ValidatePackageRelativePath("package.json bin", bin); err != nil {
			return "", err
		}
		return filepath.Clean(bin), nil
	case map[string]any:
		if serviceName != "" {
			value, ok := bin[serviceName]
			if !ok {
				return "", fmt.Errorf("package.json bin missing entry for service %q", serviceName)
			}
			target, ok := value.(string)
			if !ok {
				return "", fmt.Errorf("package.json bin %q target must be a string", serviceName)
			}
			if err := domain.ValidatePackageRelativePath("package.json bin", target); err != nil {
				return "", err
			}
			return filepath.Clean(target), nil
		}
		if len(bin) != 1 {
			return "", fmt.Errorf("package.json bin must contain exactly one entry, got %d", len(bin))
		}
		for name, value := range bin {
			target, ok := value.(string)
			if !ok {
				return "", fmt.Errorf("package.json bin %q target must be a string", name)
			}
			if err := domain.ValidatePackageRelativePath("package.json bin", target); err != nil {
				return "", err
			}
			return filepath.Clean(target), nil
		}
	}
	return "", errors.New("package.json bin is required")
}

func validatePackageFile(packageDir, rel, kind string) error {
	if err := domain.ValidatePackageRelativePath(kind, rel); err != nil {
		return err
	}
	full := filepath.Join(packageDir, rel)
	cleanPackageDir, err := filepath.Abs(packageDir)
	if err != nil {
		return err
	}
	cleanFull, err := filepath.Abs(full)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(cleanPackageDir, cleanFull)
	if err != nil {
		return err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("%s %q must stay inside package", kind, rel)
	}
	info, err := os.Stat(cleanFull)
	if err != nil {
		return fmt.Errorf("%s %q does not exist: %w", kind, rel, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %q must be a regular file", kind, rel)
	}
	return nil
}

func prepareRuntime(ctx context.Context, runtimeDir string, offline, reinstall bool) error {
	if reinstall {
		if err := os.RemoveAll(filepath.Join(runtimeDir, "node_modules")); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "package.json")); err != nil {
		return nil
	}
	if !reinstall && runtimeDependenciesInstalled(runtimeDir) {
		return nil
	}
	if !packageLocalFileDependenciesAvailable(runtimeDir) {
		return nil
	}
	return npmInstall(ctx, runtimeDir, offline, true)
}

func runtimeDependenciesInstalled(runtimeDir string) bool {
	deps, err := packageDependencies(runtimeDir)
	if err != nil {
		return false
	}
	for name := range deps {
		if _, err := os.Stat(filepath.Join(runtimeDir, "node_modules", filepath.FromSlash(name))); err != nil {
			return false
		}
	}
	if len(deps) == 0 {
		if _, err := os.Stat(filepath.Join(runtimeDir, "node_modules")); err == nil {
			return true
		}
	}
	return len(deps) > 0
}

func packageLocalFileDependenciesAvailable(runtimeDir string) bool {
	deps, err := packageDependencies(runtimeDir)
	if err != nil {
		return false
	}
	for _, spec := range deps {
		if !strings.HasPrefix(spec, "file:") {
			continue
		}
		rel := strings.TrimPrefix(spec, "file:")
		if err := domain.ValidatePackageRelativePath("file dependency", rel); err != nil {
			return false
		}
		if _, err := os.Stat(filepath.Join(runtimeDir, rel)); err != nil {
			return false
		}
	}
	return true
}

func packageDependencies(packageDir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(packageDir, "package.json"))
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, err
	}
	return pkg.Dependencies, nil
}

func npmInstall(ctx context.Context, dir string, offline, omitDev bool) error {
	args := []string{"install", "--omit=dev"}
	if !omitDev {
		args = []string{"install"}
	}
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err == nil {
		args[0] = "ci"
	} else if _, err := os.Stat(filepath.Join(dir, "npm-shrinkwrap.json")); err == nil {
		args[0] = "ci"
	}
	if offline {
		args = append(args, "--offline")
	}
	return runNPM(ctx, dir, args)
}

func npmPack(ctx context.Context, dir, destination string) (string, error) {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return "", err
	}
	out, err := runNPMOutput(ctx, dir, []string{"pack", "--pack-destination", destination})
	if err != nil {
		return "", err
	}
	packed := strings.TrimSpace(out)
	if idx := strings.LastIndex(packed, "\n"); idx >= 0 {
		packed = strings.TrimSpace(packed[idx+1:])
	}
	if packed == "" {
		return "", errors.New("npm pack did not produce a .tgz artifact")
	}
	return filepath.Join(destination, filepath.Base(packed)), nil
}

func runNPM(ctx context.Context, dir string, args []string) error {
	_, err := runNPMOutput(ctx, dir, args)
	return err
}

func runNPMOutput(ctx context.Context, dir string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = dir
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("npm %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func replaceServiceDir(serviceDir, preparedDir string) (func() error, func() error, error) {
	parent := filepath.Dir(serviceDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, nil, err
	}
	backupDir := filepath.Join(parent, "."+filepath.Base(serviceDir)+".previous")
	if err := os.RemoveAll(backupDir); err != nil {
		return nil, nil, err
	}
	hadPrevious := false
	if _, err := os.Stat(serviceDir); err == nil {
		hadPrevious = true
		if err := os.Rename(serviceDir, backupDir); err != nil {
			return nil, nil, err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	if err := os.Rename(preparedDir, serviceDir); err != nil {
		if hadPrevious {
			_ = os.Rename(backupDir, serviceDir)
		}
		return nil, nil, err
	}
	rollback := func() error {
		if err := os.RemoveAll(serviceDir); err != nil {
			return err
		}
		if hadPrevious {
			return os.Rename(backupDir, serviceDir)
		}
		return nil
	}
	cleanup := func() error {
		return os.RemoveAll(backupDir)
	}
	return rollback, cleanup, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if info.Mode().Type() != 0 {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func tarGzDir(src, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == src {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && info.Mode().Type() != 0 {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(filepath.Join("package", rel))
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
}

func untarGz(src, dst string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe archive path %q", hdr.Name)
		}
		target := filepath.Join(dst, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode).Perm()); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode).Perm())
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
}

func unzip(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, file := range r.File {
		clean := filepath.Clean(file.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe archive path %q", file.Name)
		}
		target := filepath.Join(dst, clean)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, file.Mode().Perm()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, file.Mode().Perm())
		if err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeIn := in.Close()
		closeOut := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeIn != nil {
			return closeIn
		}
		if closeOut != nil {
			return closeOut
		}
	}
	return nil
}

func normalizePackageDir(root string) string {
	if _, err := os.Stat(filepath.Join(root, "service.json")); err == nil {
		return root
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return root
	}
	return filepath.Join(root, entries[0].Name())
}
