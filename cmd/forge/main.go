package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/demo"
	"idena-git-forge/internal/gitutil"
	"idena-git-forge/internal/idena"
	"idena-git-forge/internal/protocol"
	radicleforge "idena-git-forge/internal/radicle"
	"idena-git-forge/internal/webui"
)

const version = "0.6.3"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "forge:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		printUsage(io.Writer(os.Stdout))
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch arguments[0] {
	case "demo":
		return runDemo(ctx, arguments[1:])
	case "reduce":
		return runReduce(ctx, arguments[1:])
	case "verify":
		return runVerify(ctx, arguments[1:])
	case "replay":
		return runReplay(ctx, arguments[1:])
	case "scan":
		return runScan(ctx, arguments[1:])
	case "serve":
		return runServe(ctx, arguments[1:])
	case "export-ui":
		return runExportUI(arguments[1:])
	case "share-ui":
		return runShareUI(ctx, arguments[1:])
	case "apply":
		return runApply(ctx, arguments[1:])
	case "restore":
		return runRestore(ctx, arguments[1:])
	case "retain":
		return runRetain(ctx, arguments[1:])
	case "prune":
		return runPrune(ctx, arguments[1:])
	case "gc":
		return runGC(ctx, arguments[1:])
	case "action":
		return runAction(ctx, arguments[1:])
	case "anchor":
		return runAnchor(ctx, arguments[1:])
	case "publish":
		return runPublish(ctx, arguments[1:])
	case "mirror":
		return runMirror(ctx, arguments[1:])
	case "verify-mirror":
		return runVerifyMirror(arguments[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func runDemo(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	out := flags.String("out", ".forge-demo", "new output directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	result, err := demo.Run(ctx, *out)
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func runReduce(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("reduce", flag.ContinueOnError)
	inputPath := flags.String("input", "", "checkpoint input JSON")
	contentDir := flags.String("content", "", "content store directory")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	outputPath := flags.String("out", "", "checkpoint output JSON")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *inputPath == "" || *contentDir == "" || *outputPath == "" {
		return errors.New("--input, --content and --out are required")
	}
	inputs, err := readCheckpointHistory(*inputPath)
	if err != nil {
		return err
	}
	rpcClient := idena.NewClient(*rpcEndpoint, apiKey)
	authenticated, _, err := authenticateCheckpointHistory(ctx, rpcClient, inputs, *maxScan)
	if err != nil {
		return fmt.Errorf("authenticate reducer history: %w", err)
	}
	results, err := reduceHistory(ctx, authenticated, *contentDir, *radBin, *radHome)
	if err != nil {
		return err
	}
	return writeJSON(*outputPath, results[len(results)-1])
}

func runVerify(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	inputPath := flags.String("input", "", "checkpoint input JSON")
	contentDir := flags.String("content", "", "content store directory")
	checkpointPath := flags.String("checkpoint", "", "expected checkpoint JSON")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *inputPath == "" || *contentDir == "" || *checkpointPath == "" {
		return errors.New("--input, --content and --checkpoint are required")
	}
	inputs, err := readCheckpointHistory(*inputPath)
	if err != nil {
		return err
	}
	var expected protocol.CheckpointResult
	if err := readJSON(*checkpointPath, &expected); err != nil {
		return err
	}
	verification, computed, _, err := verifyCheckpointHistoryResult(ctx, inputs, expected, *rpcEndpoint, apiKey, *maxScan, *contentDir, *radBin, *radHome)
	if err != nil {
		return err
	}
	fmt.Printf("verified %s for epoch %d at block %d (%s, %d inline actions)\n", computed.InputDigest, computed.Checkpoint.Epoch, computed.Checkpoint.Height, verification.CheckpointMode, verification.Actions)
	return nil
}

func runReplay(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	inputPath := flags.String("input", "", "JSON array of checkpoint inputs")
	contentDir := flags.String("content", "", "content store directory")
	outputPath := flags.String("out", "", "JSON array of checkpoint results")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in one settlement epoch")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *inputPath == "" || *contentDir == "" || *outputPath == "" {
		return errors.New("--input, --content and --out are required")
	}
	data, err := os.ReadFile(*inputPath)
	if err != nil {
		return err
	}
	var inputs []protocol.CheckpointInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		return err
	}
	rpcClient := idena.NewClient(*rpcEndpoint, apiKey)
	authenticated, _, err := authenticateCheckpointHistory(ctx, rpcClient, inputs, *maxScan)
	if err != nil {
		return err
	}
	results, err := reduceHistory(ctx, authenticated, *contentDir, *radBin, *radHome)
	if err != nil {
		return err
	}
	return writeJSON(*outputPath, results)
}

func runScan(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	var verifyRPCEndpoints stringList
	var verifyAPIKeyEnvs stringList
	flags.Var(&verifyRPCEndpoints, "verify-rpc", "optional replica Idena node JSON-RPC endpoint; repeat for additional node views")
	flags.Var(&verifyAPIKeyEnvs, "verify-api-key-env", "environment variable containing the API key for the matching --verify-rpc; repeat in the same order")
	identityProofs := flags.String("identity-proofs", "auto", "identity proof source: auto, rpc, or indexer")
	indexerEndpoint := flags.String("idena-api", "https://api.idena.io/api", "Idena indexer API endpoint")
	contentDir := flags.String("content", "", "content store directory")
	historyPath := flags.String("history", "", "optional JSON array of every prior checkpoint input from the forge activation checkpoint")
	historyOutputPath := flags.String("history-out", "", "optional atomically updated consecutive checkpoint history")
	outputPath := flags.String("out", "", "checkpoint input output path")
	checkpointPath := flags.String("checkpoint-out", "", "optional reduced checkpoint output")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks to scan backward")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	verifyAPIKey, err := resolveSecretEnvironment("IDENA_VERIFY_API_KEY")
	if err != nil {
		return err
	}
	resolvedVerifyAPIKeys, err := replicaAPIKeys(verifyRPCEndpoints, verifyAPIKeyEnvs, verifyAPIKey, os.LookupEnv, os.Unsetenv)
	if err != nil {
		return err
	}
	if *contentDir == "" || *outputPath == "" {
		return errors.New("--content and --out are required")
	}
	var history []protocol.CheckpointInput
	if *historyPath != "" {
		history, err = readCheckpointHistoryAllowEmpty(*historyPath)
		if err != nil {
			return err
		}
	}
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	rpcClient := idena.NewClient(*rpcEndpoint, apiKey)
	var proofSource idena.IdentityProofSource
	switch *identityProofs {
	case "rpc":
		proofSource = rpcClient
	case "indexer":
		proofSource = idena.NewIndexerProofSource(*indexerEndpoint)
	case "auto":
		proofSource = idena.AutoIdentityProofSource{
			RPC:     rpcClient,
			Indexer: idena.NewIndexerProofSource(*indexerEndpoint),
		}
	default:
		return errors.New("--identity-proofs must be auto, rpc, or indexer")
	}
	scanner := &idena.Scanner{
		Client:      rpcClient,
		ProofSource: proofSource,
		Store:       store,
		BindingVerifier: func(envelope protocol.Envelope) error {
			return radicleforge.VerifyBinding(ctx, envelope)
		},
		MaxScan: *maxScan,
	}
	scan, err := scanner.ScanLatest(ctx)
	if err != nil {
		return err
	}
	if *historyOutputPath != "" {
		if err := protocol.VerifyEpochProof(scan.Input.Checkpoint.EpochProof, scan.Input.Checkpoint.StateRoot, scan.Input.Checkpoint.Epoch+1); err != nil {
			return fmt.Errorf("refuse to archive checkpoint without a portable epoch proof: %w", err)
		}
	}
	verifyClients := make([]*idena.Client, 0, len(verifyRPCEndpoints))
	for index, endpoint := range verifyRPCEndpoints {
		verifyClient := idena.NewClient(endpoint, resolvedVerifyAPIKeys[index])
		verifyClients = append(verifyClients, verifyClient)
	}
	verifiers := make([]checkpointReplicaVerifier, len(verifyClients))
	for index := range verifyClients {
		verifiers[index] = verifyClients[index]
	}
	if err := verifyCheckpointReplicas(ctx, verifiers, scan.Input, *maxScan); err != nil {
		return err
	}

	var authenticated []protocol.AuthenticatedCheckpointInput
	if *historyOutputPath != "" || *checkpointPath != "" {
		history, _, err = appendCheckpointHistory(history, scan.Input)
		if err != nil {
			return err
		}
		authenticated, _, err = authenticateCheckpointHistory(ctx, rpcClient, history, *maxScan)
		if err != nil {
			return fmt.Errorf("authenticate scanned checkpoint history: %w", err)
		}
		for index, verifyClient := range verifyClients {
			if _, _, err := authenticateCheckpointHistory(ctx, verifyClient, history, *maxScan); err != nil {
				return fmt.Errorf("authenticate scanned checkpoint history on replica %d: %w", index+1, err)
			}
		}
	}

	if err := writeJSONAtomic(*outputPath, scan.Input); err != nil {
		return err
	}
	if *historyOutputPath != "" {
		if err := writeJSONAtomic(*historyOutputPath, history); err != nil {
			return err
		}
	}
	if len(scan.MissingCIDs) > 0 {
		fmt.Fprintf(os.Stderr, "settlement pending; required content is unavailable: %s\n", strings.Join(scan.MissingCIDs, ", "))
	}
	removed, err := store.CollectGarbage(scan.Input.Checkpoint.Epoch + 1)
	if err != nil {
		return fmt.Errorf("collect expired content leases: %w", err)
	}
	if *checkpointPath != "" {
		results, err := reduceHistory(ctx, authenticated, *contentDir, *radBin, *radHome)
		if err != nil {
			return err
		}
		if err := writeJSONAtomic(*checkpointPath, results[len(results)-1]); err != nil {
			return err
		}
	}
	fmt.Printf("scanned epoch %d at checkpoint %d; removed %d expired content object(s)\n", scan.Input.Checkpoint.Epoch, scan.Input.Checkpoint.Height, len(removed))
	return nil
}

func runServe(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	checkpointPath := flags.String("checkpoint", "", "checkpoint JSON")
	contentDir := flags.String("content", "", "content store directory")
	address := flags.String("addr", "127.0.0.1:8080", "listen address")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *checkpointPath == "" || *contentDir == "" {
		return errors.New("--checkpoint and --content are required")
	}
	var checkpoint protocol.CheckpointResult
	if err := readJSON(*checkpointPath, &checkpoint); err != nil {
		return err
	}
	if err := protocol.ValidateCheckpointResultPolicy(checkpoint); err != nil {
		return err
	}
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	server, err := webui.New(checkpoint, store)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              *address,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownContext)
	}()
	fmt.Printf("http://%s\n", *address)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runExportUI(arguments []string) error {
	flags := flag.NewFlagSet("export-ui", flag.ContinueOnError)
	checkpointPath := flags.String("checkpoint", "", "checkpoint JSON")
	contentDir := flags.String("content", "", "content store directory")
	outputPath := flags.String("out", "", "single-file HTML output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *checkpointPath == "" || *contentDir == "" || *outputPath == "" {
		return errors.New("--checkpoint, --content and --out are required")
	}
	return exportUI(*checkpointPath, *contentDir, *outputPath)
}

func runShareUI(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("share-ui", flag.ContinueOnError)
	inputPath := flags.String("input", "", "checkpoint input JSON")
	checkpointPath := flags.String("checkpoint", "", "checkpoint JSON")
	contentDir := flags.String("content", "", "content store directory")
	outputPath := flags.String("out", "", "single-file HTML output")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	socialContract := flags.String("social-contract", webui.IdenaSocialContract, "idena.social contract address")
	socialChannel := flags.String("channel", "r/idena", "idena.social channel")
	maxFee := flags.String("max-fee", "", "maximum iDNA fee for the idena.social contract call")
	broadcast := flags.Bool("broadcast", false, "disabled; review the generated plan and post through an approved Idena client")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *broadcast {
		return errors.New("direct share-ui broadcast is disabled; review the generated .social.json plan and post it through an approved Idena client")
	}
	if *inputPath == "" || *checkpointPath == "" || *contentDir == "" || *outputPath == "" {
		return errors.New("--input, --checkpoint, --content and --out are required")
	}
	if strings.TrimSpace(*rpcEndpoint) == "" {
		return errors.New("--rpc is required")
	}
	if strings.TrimSpace(*maxFee) != "" {
		if err := validatePositiveDecimal(*maxFee); err != nil {
			return fmt.Errorf("--max-fee: %w", err)
		}
		*maxFee = strings.TrimSpace(*maxFee)
	}
	inputs, err := readCheckpointHistory(*inputPath)
	if err != nil {
		return err
	}
	var checkpoint protocol.CheckpointResult
	if err := readJSON(*checkpointPath, &checkpoint); err != nil {
		return err
	}
	if _, _, _, err := verifyCheckpointHistoryResult(ctx, inputs, checkpoint, *rpcEndpoint, apiKey, *maxScan, *contentDir, *radBin, *radHome); err != nil {
		return err
	}
	if err := exportUI(*checkpointPath, *contentDir, *outputPath); err != nil {
		return err
	}
	data, err := os.ReadFile(*outputPath)
	if err != nil {
		return err
	}
	client := idena.NewClient(*rpcEndpoint, apiKey)
	cid, err := client.IPFSAdd(ctx, data, true)
	if err != nil {
		return fmt.Errorf("add preview to Idena IPFS: %w", err)
	}
	if strings.TrimSpace(cid) == "" {
		return errors.New("Idena IPFS returned an empty CID")
	}
	var manifest webui.ExportManifest
	if err := readJSON(*outputPath+".manifest.json", &manifest); err != nil {
		return err
	}
	manifest.IPFSCID = cid
	if err := writeJSON(*outputPath+".manifest.json", manifest); err != nil {
		return err
	}
	plan, err := webui.SocialPost(checkpoint, cid, *socialChannel)
	if err != nil {
		return err
	}
	plan.Contract = *socialContract
	from, err := client.CoinbaseAddress(ctx)
	if err != nil {
		return err
	}
	argument := []idena.ContractArg{{Index: 0, Format: "string", Value: plan.Argument}}
	call := idena.ContractCallArgs{
		From:     from,
		Contract: plan.Contract,
		Method:   plan.Method,
		Amount:   plan.Amount,
		Args:     argument,
	}
	estimate, err := client.EstimateContractCall(ctx, call)
	if err != nil {
		return err
	}
	if !estimate.Success {
		return fmt.Errorf("idena.social refused the post estimate: %s", estimate.Error)
	}
	plan.From = from
	if *maxFee != "" {
		plan.MaxFee = *maxFee
	} else {
		plan.MaxFee, err = doubleDecimalSum(estimate.TxFee, estimate.GasCost)
		if err != nil {
			return fmt.Errorf("calculate maximum fee: %w", err)
		}
	}
	if err := writeJSON(*outputPath+".social.json", plan); err != nil {
		return err
	}
	fmt.Printf("ipfs://%s\n", cid)
	fmt.Printf("social plan: %s.social.json\n", *outputPath)
	fmt.Println("idena.social post not sent; review the plan and post it through an approved Idena client")
	return nil
}

func doubleDecimalSum(left, right string) (string, error) {
	a, ok := new(big.Rat).SetString(strings.TrimSpace(left))
	if !ok {
		return "", fmt.Errorf("invalid decimal %q", left)
	}
	b, ok := new(big.Rat).SetString(strings.TrimSpace(right))
	if !ok {
		return "", fmt.Errorf("invalid decimal %q", right)
	}
	sum := new(big.Rat).Add(a, b)
	sum.Mul(sum, big.NewRat(2, 1))
	value := sum.FloatString(18)
	value = strings.TrimRight(strings.TrimRight(value, "0"), ".")
	if value == "" {
		return "0", nil
	}
	return value, nil
}

func exportUI(checkpointPath, contentDir, outputPath string) error {
	var checkpoint protocol.CheckpointResult
	if err := readJSON(checkpointPath, &checkpoint); err != nil {
		return err
	}
	if err := protocol.ValidateCheckpointResultPolicy(checkpoint); err != nil {
		return err
	}
	store, err := content.Open(contentDir)
	if err != nil {
		return err
	}
	html, manifest, err := webui.ExportStandalone(checkpoint, store)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, html, 0o644); err != nil {
		return err
	}
	if err := writeJSON(outputPath+".manifest.json", manifest); err != nil {
		return err
	}
	fmt.Printf("%s (%d bytes, %s)\n", outputPath, manifest.HTMLBytes, manifest.HTMLSHA256)
	return nil
}

func runApply(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	inputPath := flags.String("input", "", "checkpoint input JSON")
	checkpointPath := flags.String("checkpoint", "", "checkpoint JSON")
	contentDir := flags.String("content", "", "content store directory")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *inputPath == "" || *checkpointPath == "" || *contentDir == "" {
		return errors.New("--input, --checkpoint and --content are required")
	}
	inputs, err := readCheckpointHistory(*inputPath)
	if err != nil {
		return err
	}
	var checkpoint protocol.CheckpointResult
	if err := readJSON(*checkpointPath, &checkpoint); err != nil {
		return err
	}
	_, _, results, err := verifyCheckpointHistoryResult(ctx, inputs, checkpoint, *rpcEndpoint, apiKey, *maxScan, *contentDir, *radBin, *radHome)
	if err != nil {
		return err
	}
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	client := radicleforge.Client{Binary: *radBin, Home: *radHome}
	applied := 0
	previousRepositories := map[string]struct{}{}
	if len(results) > 1 {
		for _, repository := range results[len(results)-2].Repositories {
			previousRepositories[repository.Repository] = struct{}{}
		}
	}
	type materialization struct {
		repository protocol.RepositoryResult
		winner     protocol.PRResult
		hasWinner  bool
		initialize bool
	}
	materializations := make([]materialization, 0, len(checkpoint.Repositories))
	for _, repo := range checkpoint.Repositories {
		winner, hasWinner, err := exactWinnerRevision(repo)
		if err != nil {
			return fmt.Errorf("repository %s: %w", repo.Repository, err)
		}
		_, existed := previousRepositories[repo.Repository]
		materializations = append(materializations, materialization{
			repository: repo,
			winner:     winner,
			hasWinner:  hasWinner,
			initialize: !existed && repo.PreviousHead != "",
		})
	}
	for _, target := range materializations {
		if target.initialize {
			if err := client.WriteGenesisHead(ctx, target.repository.Repository, target.repository.PreviousHead); err != nil {
				return err
			}
			applied++
		}
		if !target.hasWinner {
			continue
		}
		bundle, err := store.Get(target.winner.BundleCID)
		if err != nil {
			return fmt.Errorf("load exact winner bundle: %w", err)
		}
		if err := client.ImportBundle(ctx, target.repository.Repository, target.winner.Author, bundle); err != nil {
			return err
		}
		if err := client.WriteGovernanceHead(ctx, target.repository.Repository, checkpoint.Checkpoint.Epoch, target.winner.Head); err != nil {
			return err
		}
		applied++
	}
	fmt.Printf("materialized %d authenticated Radicle governance ref(s)\n", applied)
	return nil
}

func exactWinnerRevision(repository protocol.RepositoryResult) (protocol.PRResult, bool, error) {
	if repository.Winner == "" {
		if repository.WinnerRevision != "" {
			return protocol.PRResult{}, false, errors.New("winner revision is set without a winning patch")
		}
		return protocol.PRResult{}, false, nil
	}
	if repository.WinnerRevision == "" {
		return protocol.PRResult{}, false, errors.New("winning patch has no exact winner revision")
	}
	var winner *protocol.PRResult
	for index := range repository.PRs {
		candidate := &repository.PRs[index]
		if candidate.PR != repository.Winner || candidate.Revision != repository.WinnerRevision {
			continue
		}
		if winner != nil {
			return protocol.PRResult{}, false, errors.New("exact winner revision is duplicated")
		}
		winner = candidate
	}
	if winner == nil {
		return protocol.PRResult{}, false, errors.New("exact winner revision is absent from checkpoint PRs")
	}
	if !winner.Eligible {
		return protocol.PRResult{}, false, errors.New("exact winner revision is not eligible")
	}
	if !strings.EqualFold(winner.Head, repository.CanonicalHead) {
		return protocol.PRResult{}, false, errors.New("exact winner head differs from canonical head")
	}
	return *winner, true, nil
}

func runRetain(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("retain", flag.ContinueOnError)
	contentDir := flags.String("content", "", "content store directory")
	inputPath := flags.String("input", "", "checkpoint input JSON")
	checkpointPath := flags.String("checkpoint", "", "checkpoint JSON")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *contentDir == "" || *inputPath == "" || *checkpointPath == "" {
		return errors.New("--content, --input and --checkpoint are required")
	}
	inputs, err := readCheckpointHistory(*inputPath)
	if err != nil {
		return err
	}
	var checkpoint protocol.CheckpointResult
	if err := readJSON(*checkpointPath, &checkpoint); err != nil {
		return err
	}
	if _, _, _, err := verifyCheckpointHistoryResult(ctx, inputs, checkpoint, *rpcEndpoint, apiKey, *maxScan, *contentDir, *radBin, *radHome); err != nil {
		return err
	}
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	objects, err := acceptedRetentionObjects(inputs[len(inputs)-1], checkpoint)
	if err != nil {
		return err
	}
	rpcClient := idena.NewClient(*rpcEndpoint, apiKey)
	nativePinned := make(map[string]struct{})
	for _, object := range objects {
		data, err := store.Get(object.CID)
		if err != nil {
			return fmt.Errorf("cannot retain missing content %s: %w", object.CID, err)
		}
		if _, exists := nativePinned[object.CID]; !exists {
			added, err := rpcClient.IPFSAdd(ctx, data, true)
			if err != nil {
				return fmt.Errorf("pin accepted content %s in the local Idena node: %w", object.CID, err)
			}
			if added != object.CID {
				return fmt.Errorf("Idena node pinned %s for accepted content %s", added, object.CID)
			}
			nativePinned[object.CID] = struct{}{}
		}
		if err := store.PinRepository(object.CID, object.Repository); err != nil {
			return err
		}
	}
	fmt.Printf("retained %d accepted repository object binding(s) across %d Idena IPFS pin(s)\n", len(objects), len(nativePinned))
	return nil
}

type retentionObject struct {
	CID        string
	Repository string
}

func acceptedRetentionObjects(input protocol.CheckpointInput, checkpoint protocol.CheckpointResult) ([]retentionObject, error) {
	rejected := make(map[string]struct{}, len(checkpoint.Rejected))
	for _, item := range checkpoint.Rejected {
		if item.TxHash != "" {
			rejected[strings.ToLower(item.TxHash)] = struct{}{}
		}
	}
	seen := make(map[string]struct{})
	var objects []retentionObject
	for _, action := range input.Actions {
		if _, exists := rejected[strings.ToLower(action.TxHash)]; exists {
			continue
		}
		envelope, err := protocol.ParseEnvelope(action.ActionBytes)
		if err != nil {
			return nil, fmt.Errorf("accepted action %s is invalid: %w", action.TxHash, err)
		}
		payload, err := envelope.DecodePayload()
		if err != nil {
			return nil, fmt.Errorf("decode accepted action %s: %w", action.TxHash, err)
		}
		cids := append([]string{action.ActionCID}, idena.ContentCIDs(payload)...)
		for _, contentCID := range cids {
			if err := content.ValidateCID(contentCID); err != nil {
				return nil, fmt.Errorf("accepted action %s content: %w", action.TxHash, err)
			}
			key := envelope.Repository + "\x00" + contentCID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			objects = append(objects, retentionObject{CID: contentCID, Repository: envelope.Repository})
		}
	}
	return objects, nil
}

func runPrune(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("prune", flag.ContinueOnError)
	inputPath := flags.String("input", "", "checkpoint input JSON")
	checkpointPath := flags.String("checkpoint", "", "expected checkpoint JSON")
	contentDir := flags.String("content", "", "content store directory")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	currentEpoch := flags.Uint("current-epoch", 0, "optional expected current Idena epoch")
	repository := flags.String("repository", "", "optional repository RID to prune")
	deleteContent := flags.Bool("delete", false, "delete eligible content after a verified deletion decision")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *inputPath == "" || *checkpointPath == "" || *contentDir == "" {
		return errors.New("--input, --checkpoint and --content are required")
	}
	if *currentEpoch > 0xffff {
		return errors.New("--current-epoch exceeds the protocol epoch range")
	}
	inputs, err := readCheckpointHistory(*inputPath)
	if err != nil {
		return err
	}
	var expected protocol.CheckpointResult
	if err := readJSON(*checkpointPath, &expected); err != nil {
		return err
	}
	if _, _, _, err := verifyCheckpointHistoryResult(ctx, inputs, expected, *rpcEndpoint, apiKey, *maxScan, *contentDir, *radBin, *radHome); err != nil {
		return err
	}
	rpcClient := idena.NewClient(*rpcEndpoint, apiKey)
	epoch, err := rpcClient.Epoch(ctx)
	if err != nil {
		return err
	}
	if *currentEpoch != 0 && uint16(*currentEpoch) != epoch.Epoch {
		return fmt.Errorf("--current-epoch %d differs from canonical node epoch %d", *currentEpoch, epoch.Epoch)
	}
	*currentEpoch = uint(epoch.Epoch)
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	plans := make([]map[string]any, 0)
	found := false
	for _, repo := range expected.Repositories {
		if !repo.Deleted || (*repository != "" && repo.Repository != *repository) {
			continue
		}
		found = true
		objects, err := store.RepositoryObjects(repo.Repository)
		if err != nil {
			return err
		}
		eligible := uint16(*currentEpoch) >= repo.PruneAfterEpoch
		removed := []string{}
		if eligible && *deleteContent {
			removed, err = store.PruneRepository(repo.Repository, uint16(*currentEpoch), repo.PruneAfterEpoch)
			if err != nil {
				return err
			}
		}
		plans = append(plans, map[string]any{
			"repository":      repo.Repository,
			"objects":         objects,
			"pruneAfterEpoch": repo.PruneAfterEpoch,
			"eligible":        eligible,
			"removed":         removed,
		})
	}
	if *repository != "" && !found {
		return fmt.Errorf("repository %s has no deletion decision in the checkpoint", *repository)
	}
	printJSON(map[string]any{
		"currentEpoch": *currentEpoch,
		"delete":       *deleteContent,
		"repositories": plans,
	})
	return nil
}

func runGC(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("gc", flag.ContinueOnError)
	contentDir := flags.String("content", "", "content store directory")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	currentEpoch := flags.Uint("current-epoch", 0, "optional expected current Idena epoch")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *contentDir == "" {
		return errors.New("--content is required")
	}
	if *currentEpoch > 0xffff {
		return errors.New("--current-epoch exceeds the protocol epoch range")
	}
	client := idena.NewClient(*rpcEndpoint, apiKey)
	epoch, err := client.Epoch(ctx)
	if err != nil {
		return err
	}
	if *currentEpoch != 0 && uint16(*currentEpoch) != epoch.Epoch {
		return fmt.Errorf("--current-epoch %d differs from canonical node epoch %d", *currentEpoch, epoch.Epoch)
	}
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	removed, err := store.CollectGarbage(epoch.Epoch)
	if err != nil {
		return err
	}
	printJSON(map[string]any{
		"currentEpoch": epoch.Epoch,
		"removed":      removed,
	})
	return nil
}

func runRestore(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	inputPath := flags.String("input", "", "checkpoint input JSON")
	contentDir := flags.String("content", "", "content store directory")
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	maxScan := flags.Uint64("max-scan", 250_000, "maximum blocks in the settlement epoch")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *inputPath == "" || *contentDir == "" {
		return errors.New("--input and --content are required")
	}
	input, err := readCheckpointInput(*inputPath)
	if err != nil {
		return err
	}
	rpcClient := idena.NewClient(*rpcEndpoint, apiKey)
	if _, err := rpcClient.VerifyCheckpointInput(ctx, input, *maxScan); err != nil {
		return fmt.Errorf("authenticate restore input: %w", err)
	}
	store, err := content.Open(*contentDir)
	if err != nil {
		return err
	}
	client := radicleforge.Client{Binary: *radBin, Home: *radHome}
	recognized, rejected, err := protocol.RecognizeActions(input, func(envelope protocol.Envelope) error {
		return radicleforge.VerifyBinding(ctx, envelope)
	})
	if err != nil {
		return err
	}
	ordered := make([]protocol.RecognizedAction, 0, len(recognized))
	for _, action := range recognized {
		if action.Envelope.Kind == protocol.KindRepository {
			ordered = append(ordered, action)
		}
	}
	for _, action := range recognized {
		if action.Envelope.Kind != protocol.KindRepository {
			ordered = append(ordered, action)
		}
	}
	imported := make(map[string]struct{})
	var failures []string
	for _, action := range ordered {
		subject := action.Subject
		if subject.BundleCID == "" {
			continue
		}
		key := action.Envelope.Repository + "\x00" + action.Envelope.RadicleDID + "\x00" + subject.BundleCID
		if _, exists := imported[key]; exists {
			continue
		}
		bundle, err := store.Get(subject.BundleCID)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: load bundle: %v", action.Order.TxHash, err))
			continue
		}
		if err := client.ImportBundle(ctx, action.Envelope.Repository, action.Envelope.RadicleDID, bundle); err != nil {
			failures = append(failures, fmt.Sprintf("%s: import bundle %s: %v", action.Order.TxHash, subject.BundleCID, err))
			continue
		}
		imported[key] = struct{}{}
	}
	fmt.Printf("restored %d authenticated actor bundle(s); skipped %d rejected action(s)\n", len(imported), len(rejected))
	if len(failures) > 0 {
		return fmt.Errorf("%d bundle import(s) failed after independent actions were processed: %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

func runAction(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("action", flag.ContinueOnError)
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	kind := flags.String("kind", "", "action kind")
	repository := flags.String("repo", "", "owner/name")
	epoch := flags.Uint("epoch", 0, "publication epoch")
	payloadPath := flags.String("payload", "", "payload JSON file")
	nonce := flags.String("nonce", "", "optional 16-byte hex nonce")
	outputPath := flags.String("out", "", "signed action output")
	radHome := flags.String("rad-home", defaultRadHome(), "Radicle home")
	radKey := flags.String("rad-key", "", "Radicle signing key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *kind == "" || *repository == "" || *epoch == 0 || *payloadPath == "" || *outputPath == "" {
		return errors.New("--kind, --repo, --epoch, --payload and --out are required")
	}
	payloadData, err := os.ReadFile(*payloadPath)
	if err != nil {
		return err
	}
	client := idena.NewClient(*rpcEndpoint, apiKey)
	author, err := client.CoinbaseAddress(ctx)
	if err != nil {
		return err
	}
	if *nonce == "" {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return err
		}
		*nonce = hex.EncodeToString(nonceBytes)
	}
	if *radKey == "" {
		*radKey = filepath.Join(*radHome, "keys", "radicle")
	}
	publicKey, err := os.ReadFile(*radKey + ".pub")
	if err != nil {
		return fmt.Errorf("read Radicle public key: %w", err)
	}
	did, _, err := radicleforge.DIDForKey(string(publicKey))
	if err != nil {
		return err
	}
	envelope, err := protocol.NewEnvelope(*kind, *repository, uint16(*epoch), author, did, string(publicKey), *nonce, json.RawMessage(payloadData))
	if err != nil {
		return err
	}
	binding, err := radicleforge.SignBinding(ctx, *radKey, envelope.RadicleBindingMessage())
	if err != nil {
		return err
	}
	envelope.Binding = binding
	if err := radicleforge.VerifyBinding(ctx, *envelope); err != nil {
		return err
	}
	unsigned, err := envelope.UnsignedBytes()
	if err != nil {
		return err
	}
	signature, err := client.Sign(ctx, string(unsigned))
	if err != nil {
		return err
	}
	if err := envelope.AttachSignature(signature); err != nil {
		return err
	}
	encoded, err := envelope.Bytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outputPath, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s action for %s; output %s\n", envelope.Kind, envelope.Author, *outputPath)
	return nil
}

func runAnchor(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("anchor", flag.ContinueOnError)
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	radPassphraseEnvironment := flags.String("rad-passphrase-env", "RAD_PASSPHRASE", "environment variable containing the Radicle key passphrase")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "Radicle home")
	radKey := flags.String("rad-key", "", "Radicle signing key")
	rid := flags.String("rid", "", "Radicle repository ID")
	kind := flags.String("kind", "", "radicle_repository, radicle_patch, radicle_issue, radicle_review, or radicle_merge_label")
	head := flags.String("head", "", "Git head OID for a repository anchor")
	patchID := flags.String("patch", "", "Radicle patch ID")
	revisionID := flags.String("revision", "", "Radicle exact revision ID")
	subjectID := flags.String("subject", "", "Radicle COB/action OID for issue, review, or label")
	reviewID := flags.String("review", "", "Radicle review COB ID; defaults to --subject")
	decision := flags.String("decision", "", "approve or reject")
	deleteRepository := flags.Bool("delete-repository", false, "mark a passing PR as the one-epoch-delayed repository deletion decision")
	nonce := flags.String("nonce", "", "optional 16-byte anchor nonce")
	txNonce := flags.Uint("tx-nonce", 0, "Idena account nonce for transaction estimation and later publication")
	maxFee := flags.String("max-fee", "", "maximum iDNA fee for the forge action transaction")
	out := flags.String("out", "", "signed anchor output")
	bundleOut := flags.String("bundle-out", "", "write the exported Radicle storage bundle")
	diffOut := flags.String("diff-out", "", "write the exact patch diff for later reviewed publication")
	prepareOnly := flags.Bool("prepare-only", false, "sign and save local artifacts without adding them to Idena IPFS")
	broadcast := flags.Bool("broadcast", false, "disabled; use forge publish with the approved transaction hash and fee")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	radPassphrase, err := resolveSecretEnvironment(*radPassphraseEnvironment)
	if err != nil {
		return err
	}
	if *broadcast {
		return errors.New("direct anchor broadcast is disabled; prepare the action and use forge publish with the approved transaction hash and fee")
	}
	if *rpcEndpoint == "" || *rid == "" || *kind == "" {
		return errors.New("--rpc, --rid and --kind are required")
	}
	if *prepareOnly && (*out == "" || *bundleOut == "") {
		return errors.New("--prepare-only requires --out and --bundle-out")
	}
	if *prepareOnly && *kind == protocol.KindPullRequest && *diffOut == "" {
		return errors.New("--prepare-only for a Radicle patch requires --diff-out")
	}
	if strings.TrimSpace(*maxFee) != "" {
		if err := validatePositiveDecimal(*maxFee); err != nil {
			return fmt.Errorf("--max-fee: %w", err)
		}
		*maxFee = strings.TrimSpace(*maxFee)
	}
	if *radKey == "" {
		*radKey = filepath.Join(*radHome, "keys", "radicle")
	}
	radicleClient := radicleforge.Client{Binary: *radBin, Home: *radHome, Passphrase: radPassphrase}
	if err := radicleClient.ValidateProfile(); err != nil {
		return err
	}
	idenaClient := idena.NewClient(*rpcEndpoint, apiKey)
	epoch, err := idenaClient.Epoch(ctx)
	if err != nil {
		return err
	}
	bundle, err := radicleClient.ExportBundle(ctx, *rid)
	if err != nil {
		return err
	}
	bundleCID, err := prepareContentCID(ctx, idenaClient, bundle, *prepareOnly)
	if err != nil {
		return fmt.Errorf("prepare Radicle bundle: %w", err)
	}
	if *bundleOut != "" {
		if err := os.MkdirAll(filepath.Dir(*bundleOut), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(*bundleOut, bundle, 0o644); err != nil {
			return err
		}
	}
	var payload any
	switch *kind {
	case protocol.KindRepository:
		if *head == "" {
			return errors.New("--head is required for a repository anchor")
		}
		payload = protocol.RepositoryPayload{Head: *head, Bundle: bundleCID}
	case protocol.KindPullRequest:
		if *patchID == "" || *revisionID == "" {
			return errors.New("--patch and --revision are required for a Radicle patch anchor")
		}
		state, err := radicleClient.PatchState(ctx, *rid, *patchID)
		if err != nil {
			return err
		}
		revision, exists := state.Revisions[*revisionID]
		if !exists {
			return errors.New("Radicle revision is absent from patch state")
		}
		diff, err := radicleClient.PatchDiff(ctx, *rid, *patchID, *revisionID)
		if err != nil {
			return err
		}
		diffCID, err := prepareContentCID(ctx, idenaClient, diff, *prepareOnly)
		if err != nil {
			return fmt.Errorf("prepare patch diff: %w", err)
		}
		if *diffOut != "" {
			if err := os.MkdirAll(filepath.Dir(*diffOut), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(*diffOut, diff, 0o644); err != nil {
				return err
			}
		}
		payload = protocol.PullRequestPayload{
			Patch: *patchID, Revision: *revisionID, Title: state.Title,
			Base: revision.Base, Head: revision.OID, Bundle: bundleCID, Diff: diffCID,
			DeleteRepository: *deleteRepository,
		}
	case protocol.KindIssue:
		if *subjectID == "" {
			return errors.New("--subject is required for an issue anchor")
		}
		state, err := radicleClient.CobShow(ctx, *rid, radicleforge.IssueType, *subjectID)
		if err != nil {
			return err
		}
		var issue struct {
			Title string `json:"title"`
		}
		if err := json.Unmarshal(state, &issue); err != nil {
			return err
		}
		payload = protocol.IssuePayload{Issue: *subjectID, Action: *subjectID, Title: issue.Title, Bundle: bundleCID}
	case protocol.KindVote:
		if *patchID == "" || *revisionID == "" || *subjectID == "" || *decision == "" {
			return errors.New("--patch, --revision, --subject and --decision are required for a review anchor")
		}
		if *decision != protocol.DecisionApprove && *decision != protocol.DecisionReject {
			return errors.New("--decision must be approve or reject")
		}
		if *reviewID == "" {
			*reviewID = *subjectID
		}
		payload = protocol.VotePayload{
			Patch: *patchID, Revision: *revisionID, Decision: *decision,
			Review: *reviewID, ActionOID: *subjectID, Bundle: bundleCID,
		}
	case protocol.KindMergeRequest:
		if *patchID == "" || *revisionID == "" || *subjectID == "" {
			return errors.New("--patch, --revision and --subject are required for a merge-label anchor")
		}
		payload = protocol.MergeRequestPayload{
			Patch: *patchID, Revision: *revisionID, Label: radicleforge.MergeRequestLabel,
			LabelAction: *subjectID, Bundle: bundleCID,
		}
	default:
		return fmt.Errorf("unsupported Radicle anchor kind %q", *kind)
	}

	author, err := idenaClient.CoinbaseAddress(ctx)
	if err != nil {
		return err
	}
	publicKey, err := os.ReadFile(*radKey + ".pub")
	if err != nil {
		return err
	}
	did, _, err := radicleforge.DIDForKey(string(publicKey))
	if err != nil {
		return err
	}
	if *nonce == "" {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return err
		}
		*nonce = hex.EncodeToString(nonceBytes)
	}
	envelope, err := protocol.NewEnvelope(*kind, *rid, epoch.Epoch, author, did, string(publicKey), *nonce, withActor(payload, did))
	if err != nil {
		return err
	}
	subject, err := protocol.RadicleSubjectFor(*envelope, withActor(payload, did))
	if err != nil {
		return err
	}
	if err := radicleClient.VerifySubject(ctx, subject); err != nil {
		return fmt.Errorf("verify Radicle action: %w", err)
	}
	binding, err := radicleforge.SignBinding(ctx, *radKey, envelope.RadicleBindingMessage())
	if err != nil {
		return err
	}
	envelope.Binding = binding
	if err := radicleforge.VerifyBinding(ctx, *envelope); err != nil {
		return err
	}
	unsigned, err := envelope.UnsignedBytes()
	if err != nil {
		return err
	}
	signature, err := idenaClient.Sign(ctx, string(unsigned))
	if err != nil {
		return err
	}
	if err := envelope.AttachSignature(signature); err != nil {
		return err
	}
	encoded, err := envelope.Bytes()
	if err != nil {
		return err
	}
	actionCID, err := prepareContentCID(ctx, idenaClient, encoded, *prepareOnly)
	if err != nil {
		return err
	}
	plan := map[string]any{
		"actionCid":   actionCID,
		"bundleCid":   bundleCID,
		"epoch":       envelope.Epoch,
		"nonce":       *txNonce,
		"prepareOnly": *prepareOnly,
		"broadcast":   *broadcast,
		"transaction": "self-send with IDENA_GIT_ACTION_V1 payload",
	}
	if *maxFee != "" {
		estimate, err := idenaClient.EstimateForgeAction(ctx, author, encoded, uint32(*txNonce), envelope.Epoch, *maxFee)
		if err != nil {
			return fmt.Errorf("estimate forge action transaction: %w", err)
		}
		plan["maxFee"] = *maxFee
		plan["estimatedTxFee"] = estimate.TxFee
		plan["estimatedTxHash"] = estimate.TxHash
	}
	if *out != "" {
		if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
		plan["actionFile"] = *out
	}
	if *bundleOut != "" {
		plan["bundleFile"] = *bundleOut
	}
	if *diffOut != "" {
		plan["diffFile"] = *diffOut
	}
	printJSON(plan)
	return nil
}

func prepareContentCID(ctx context.Context, client *idena.Client, data []byte, localOnly bool) (string, error) {
	if localOnly {
		return content.CIDForBytes(data)
	}
	return uploadBytes(ctx, client, data)
}

func uploadBytes(ctx context.Context, client *idena.Client, data []byte) (string, error) {
	localCID, err := content.CIDForBytes(data)
	if err != nil {
		return "", err
	}
	nodeCID, err := client.IPFSCID(ctx, data)
	if err != nil {
		return "", err
	}
	if localCID != nodeCID {
		return "", fmt.Errorf("content CID mismatch: local %s, node %s", localCID, nodeCID)
	}
	if _, err := client.IPFSAdd(ctx, data, true); err != nil {
		return "", err
	}
	return localCID, nil
}

func withActor(payload any, did string) any {
	switch typed := payload.(type) {
	case protocol.RepositoryPayload:
		typed.ActorDID = did
		return typed
	case protocol.CommitPayload:
		typed.ActorDID = did
		return typed
	case protocol.IssuePayload:
		typed.ActorDID = did
		return typed
	case protocol.PullRequestPayload:
		typed.ActorDID = did
		return typed
	case protocol.CommentPayload:
		typed.ActorDID = did
		return typed
	case protocol.VotePayload:
		typed.ActorDID = did
		return typed
	case protocol.MergeRequestPayload:
		typed.ActorDID = did
		return typed
	default:
		return payload
	}
}

func runPublish(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	actionPath := flags.String("action", "", "signed action JSON")
	nonce := flags.Uint("nonce", 0, "account nonce")
	maxFee := flags.String("max-fee", "", "maximum iDNA fee for the forge action transaction")
	expectedTxHash := flags.String("expected-tx-hash", "", "approved transaction hash returned by bcn_estimateTx")
	expectedTxFee := flags.String("expected-tx-fee", "", "approved transaction fee returned by bcn_estimateTx")
	broadcast := flags.Bool("broadcast", false, "send the inline forge action transaction through the node")
	var objectPaths stringList
	flags.Var(&objectPaths, "object", "local referenced content file to verify and pin; may be repeated")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *broadcast && strings.TrimSpace(*maxFee) == "" {
		return errors.New("--max-fee is required with --broadcast")
	}
	if *broadcast && (strings.TrimSpace(*expectedTxHash) == "" || strings.TrimSpace(*expectedTxFee) == "") {
		return errors.New("--expected-tx-hash and --expected-tx-fee are required with --broadcast")
	}
	if strings.TrimSpace(*maxFee) != "" {
		if err := validatePositiveDecimal(*maxFee); err != nil {
			return fmt.Errorf("--max-fee: %w", err)
		}
		*maxFee = strings.TrimSpace(*maxFee)
	}
	if strings.TrimSpace(*expectedTxHash) != "" || strings.TrimSpace(*expectedTxFee) != "" {
		if *maxFee == "" {
			return errors.New("--max-fee is required with an expected transaction estimate")
		}
		if err := validateTransactionHash(*expectedTxHash); err != nil {
			return fmt.Errorf("--expected-tx-hash: %w", err)
		}
		if err := validatePositiveDecimal(*expectedTxFee); err != nil {
			return fmt.Errorf("--expected-tx-fee: %w", err)
		}
		*expectedTxHash = strings.TrimSpace(*expectedTxHash)
		*expectedTxFee = strings.TrimSpace(*expectedTxFee)
	}
	if *actionPath == "" {
		return errors.New("--action is required")
	}
	data, err := os.ReadFile(*actionPath)
	if err != nil {
		return err
	}
	envelope, err := protocol.ParseEnvelope(bytesTrimSpace(data))
	if err != nil {
		return err
	}
	payload, err := envelope.DecodePayload()
	if err != nil {
		return err
	}
	client := idena.NewClient(*rpcEndpoint, apiKey)
	epoch, err := client.Epoch(ctx)
	if err != nil {
		return err
	}
	if envelope.Epoch != epoch.Epoch {
		return fmt.Errorf("action epoch %d differs from current node epoch %d", envelope.Epoch, epoch.Epoch)
	}
	coinbase, err := client.CoinbaseAddress(ctx)
	if err != nil {
		return err
	}
	if !strings.EqualFold(coinbase, envelope.Author) {
		return errors.New("signed action author differs from the node coinbase")
	}
	var estimate *idena.ForgeActionEstimate
	if *maxFee != "" {
		result, err := client.EstimateForgeAction(ctx, coinbase, bytesTrimSpace(data), uint32(*nonce), envelope.Epoch, *maxFee)
		if err != nil {
			return fmt.Errorf("estimate forge action transaction: %w", err)
		}
		if *expectedTxHash != "" {
			if err := verifyForgeActionEstimate(result, *expectedTxHash, *expectedTxFee); err != nil {
				return err
			}
		}
		estimate = &result
	}
	localObjects := make(map[string][]byte, len(objectPaths))
	for _, path := range objectPaths {
		object, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read local content object %s: %w", path, err)
		}
		contentCID, err := content.CIDForBytes(object)
		if err != nil {
			return err
		}
		localObjects[contentCID] = object
	}
	referenced := idena.ContentCIDs(payload)
	for _, contentCID := range referenced {
		object, exists := localObjects[contentCID]
		if !exists {
			object, err = client.IPFSGet(ctx, contentCID)
			if err != nil {
				return fmt.Errorf("referenced content %s is neither supplied locally nor retrievable: %w", contentCID, err)
			}
		}
		calculated, err := content.CIDForBytes(object)
		if err != nil || calculated != contentCID {
			return fmt.Errorf("referenced content %s is not a raw SHA2-256 object", contentCID)
		}
		nodeCID, err := client.IPFSCID(ctx, object)
		if err != nil {
			return err
		}
		if nodeCID != contentCID {
			return fmt.Errorf("node CID %s differs from referenced content %s", nodeCID, contentCID)
		}
		if _, err := client.IPFSAdd(ctx, object, true); err != nil {
			return fmt.Errorf("pin referenced content %s: %w", contentCID, err)
		}
	}
	rawCID, err := content.CIDForBytes(bytesTrimSpace(data))
	if err != nil {
		return err
	}
	nodeRawCID, err := client.IPFSCID(ctx, bytesTrimSpace(data))
	if err != nil {
		return err
	}
	if rawCID != nodeRawCID {
		return fmt.Errorf("action CID mismatch: local %s, node %s", rawCID, nodeRawCID)
	}
	addedCID, err := client.IPFSAdd(ctx, bytesTrimSpace(data), true)
	if err != nil {
		return err
	}
	plan := map[string]any{
		"actionCid":     rawCID,
		"addedRoot":     addedCID,
		"epoch":         envelope.Epoch,
		"nonce":         *nonce,
		"broadcast":     *broadcast,
		"transaction":   "self-send with IDENA_GIT_ACTION_V1 payload",
		"pinnedObjects": len(referenced) + 1,
	}
	if estimate != nil {
		plan["maxFee"] = *maxFee
		plan["estimatedTxFee"] = estimate.TxFee
		plan["estimatedTxHash"] = estimate.TxHash
		plan["estimateMatchedApproval"] = *expectedTxHash != ""
	}
	if !*broadcast {
		printJSON(plan)
		return nil
	}
	txHash, err := client.SendForgeAction(ctx, coinbase, bytesTrimSpace(data), uint32(*nonce), envelope.Epoch, *maxFee)
	if err != nil {
		return err
	}
	plan["txHash"] = txHash
	printJSON(plan)
	return nil
}

func reduceHistory(ctx context.Context, inputs []protocol.AuthenticatedCheckpointInput, contentDir, radBin, radHome string) ([]protocol.CheckpointResult, error) {
	store, err := content.Open(contentDir)
	if err != nil {
		return nil, err
	}
	radicleClient := radicleforge.VerificationClient{Binary: radBin, Home: radHome}
	if err := radicleClient.ValidateProfile(); err != nil {
		return nil, err
	}
	radicleVerifier := radicleforge.ContentVerifier{Client: radicleClient, Store: store}
	return protocol.ReduceReplay(inputs, func(bundleCID, base, head string) error {
		data, err := store.Get(bundleCID)
		if err != nil {
			return fmt.Errorf("%w: Git bundle %s: %v", protocol.ErrContentUnavailable, bundleCID, err)
		}
		return gitutil.VerifyBundleAndFastForward(ctx, data, base, head)
	}, func(envelope protocol.Envelope) error {
		return radicleforge.VerifyBinding(ctx, envelope)
	}, func(subject protocol.RadicleSubject) error {
		return radicleVerifier.Verify(ctx, subject)
	})
}

func verifyCheckpointHistoryResult(
	ctx context.Context,
	inputs []protocol.CheckpointInput,
	expected protocol.CheckpointResult,
	rpcEndpoint string,
	apiKey string,
	maxScan uint64,
	contentDir string,
	radBin string,
	radHome string,
) (idena.ChainVerification, *protocol.CheckpointResult, []protocol.CheckpointResult, error) {
	if err := protocol.ValidateCheckpointResultPolicy(expected); err != nil {
		return idena.ChainVerification{}, nil, nil, fmt.Errorf("expected checkpoint: %w", err)
	}
	rpcClient := idena.NewClient(rpcEndpoint, apiKey)
	authenticated, verifications, err := authenticateCheckpointHistory(ctx, rpcClient, inputs, maxScan)
	if err != nil {
		return idena.ChainVerification{}, nil, nil, fmt.Errorf("authenticate checkpoint input: %w", err)
	}
	results, err := reduceHistory(ctx, authenticated, contentDir, radBin, radHome)
	if err != nil {
		return idena.ChainVerification{}, nil, nil, err
	}
	computed := &results[len(results)-1]
	computedBytes, err := json.Marshal(computed)
	if err != nil {
		return idena.ChainVerification{}, nil, nil, err
	}
	expectedBytes, err := json.Marshal(expected)
	if err != nil {
		return idena.ChainVerification{}, nil, nil, err
	}
	if string(computedBytes) != string(expectedBytes) {
		return idena.ChainVerification{}, nil, nil, errors.New("checkpoint output does not match the authenticated deterministic replay")
	}
	return verifications[len(verifications)-1], computed, results, nil
}

func authenticateCheckpointHistory(
	ctx context.Context,
	client *idena.Client,
	inputs []protocol.CheckpointInput,
	maxScan uint64,
) ([]protocol.AuthenticatedCheckpointInput, []idena.ChainVerification, error) {
	if len(inputs) == 0 {
		return nil, nil, errors.New("checkpoint history is empty")
	}
	for index := range inputs {
		if err := protocol.ValidateCheckpointInputPolicy(inputs[index]); err != nil {
			return nil, nil, fmt.Errorf("checkpoint history entry %d: %w", index, err)
		}
	}
	if inputs[0].Checkpoint.Epoch != protocol.MainnetActivationEpoch {
		return nil, nil, fmt.Errorf("checkpoint history must start at mainnet activation epoch %d", protocol.MainnetActivationEpoch)
	}
	for index := 1; index < len(inputs); index++ {
		if inputs[index-1].Checkpoint.Epoch == ^uint16(0) || inputs[index].Checkpoint.Epoch != inputs[index-1].Checkpoint.Epoch+1 {
			return nil, nil, fmt.Errorf("checkpoint history entry %d is not the consecutive epoch after entry %d", index, index-1)
		}
		if inputs[index].Checkpoint.Height <= inputs[index-1].Checkpoint.Height {
			return nil, nil, fmt.Errorf("checkpoint history entry %d does not follow the previous block height", index)
		}
	}
	authenticated := make([]protocol.AuthenticatedCheckpointInput, len(inputs))
	verifications := make([]idena.ChainVerification, len(inputs))
	for index := range inputs {
		var verification idena.ChainVerification
		sealed, err := protocol.AuthenticateCheckpointInput(ctx, inputs[index], func(ctx context.Context, input protocol.CheckpointInput) error {
			var verifyErr error
			verification, verifyErr = client.VerifyCheckpointInput(ctx, input, maxScan)
			return verifyErr
		})
		if err != nil {
			return nil, nil, fmt.Errorf("checkpoint history entry %d: %w", index, err)
		}
		authenticated[index] = sealed
		verifications[index] = verification
	}
	return authenticated, verifications, nil
}

func readCheckpointInput(path string) (protocol.CheckpointInput, error) {
	var input protocol.CheckpointInput
	if err := readJSON(path, &input); err != nil {
		return protocol.CheckpointInput{}, err
	}
	if err := protocol.ValidateCheckpointInputPolicy(input); err != nil {
		return protocol.CheckpointInput{}, fmt.Errorf("%s: %w", path, err)
	}
	return input, nil
}

func readCheckpointHistory(path string) ([]protocol.CheckpointInput, error) {
	inputs, err := readCheckpointHistoryAllowEmpty(path)
	if err != nil {
		return nil, err
	}
	if len(inputs) == 0 {
		return nil, errors.New("checkpoint history is empty")
	}
	return inputs, nil
}

func readCheckpointHistoryAllowEmpty(path string) ([]protocol.CheckpointInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytesTrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("checkpoint history is empty")
	}
	if trimmed[0] == '[' {
		var inputs []protocol.CheckpointInput
		if err := json.Unmarshal(trimmed, &inputs); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for index := range inputs {
			if err := protocol.ValidateCheckpointInputPolicy(inputs[index]); err != nil {
				return nil, fmt.Errorf("%s checkpoint history entry %d: %w", path, index, err)
			}
		}
		return inputs, nil
	}
	var input protocol.CheckpointInput
	if err := json.Unmarshal(trimmed, &input); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := protocol.ValidateCheckpointInputPolicy(input); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return []protocol.CheckpointInput{input}, nil
}

func appendCheckpointHistory(history []protocol.CheckpointInput, next protocol.CheckpointInput) ([]protocol.CheckpointInput, bool, error) {
	if err := protocol.ValidateCheckpointInputPolicy(next); err != nil {
		return nil, false, err
	}
	for index := range history {
		if err := protocol.ValidateCheckpointInputPolicy(history[index]); err != nil {
			return nil, false, fmt.Errorf("checkpoint history entry %d: %w", index, err)
		}
	}
	if len(history) == 0 {
		if next.Checkpoint.Epoch != protocol.MainnetActivationEpoch {
			return nil, false, fmt.Errorf("checkpoint history must start at mainnet activation epoch %d", protocol.MainnetActivationEpoch)
		}
		return []protocol.CheckpointInput{next}, true, nil
	}
	last := history[len(history)-1]
	if next.Checkpoint.Epoch == last.Checkpoint.Epoch {
		if reflect.DeepEqual(last, next) {
			return append([]protocol.CheckpointInput(nil), history...), false, nil
		}
		return nil, false, fmt.Errorf("checkpoint history already contains a different record for epoch %d", next.Checkpoint.Epoch)
	}
	if last.Checkpoint.Epoch == ^uint16(0) || next.Checkpoint.Epoch != last.Checkpoint.Epoch+1 {
		return nil, false, fmt.Errorf("checkpoint epoch %d is not consecutive after epoch %d", next.Checkpoint.Epoch, last.Checkpoint.Epoch)
	}
	if next.Checkpoint.Height <= last.Checkpoint.Height {
		return nil, false, errors.New("checkpoint height does not follow the existing history")
	}
	result := append([]protocol.CheckpointInput(nil), history...)
	return append(result, next), true, nil
}

func readJSON(path string, destination any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeJSONAtomic(path string, value any) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func printJSON(value any) {
	data, _ := json.MarshalIndent(value, "", "  ")
	fmt.Println(string(data))
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}

func validatePositiveDecimal(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("positive decimal is required")
	}
	dot := -1
	for index, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character == '.' && dot == -1:
			dot = index
		default:
			return fmt.Errorf("%q is not a positive decimal", value)
		}
	}
	if dot == 0 || dot == len(value)-1 {
		return fmt.Errorf("%q is not a positive decimal", value)
	}
	amount, ok := new(big.Rat).SetString(value)
	if !ok || amount.Sign() <= 0 {
		return fmt.Errorf("%q is not a positive decimal", value)
	}
	return nil
}

func validateTransactionHash(value string) error {
	value = strings.TrimSpace(value)
	if len(value) != 66 || !strings.HasPrefix(value, "0x") {
		return errors.New("expected a 0x-prefixed 32-byte hash")
	}
	if _, err := hex.DecodeString(value[2:]); err != nil {
		return errors.New("expected a 0x-prefixed 32-byte hash")
	}
	return nil
}

func verifyForgeActionEstimate(estimate idena.ForgeActionEstimate, expectedHash, expectedFee string) error {
	if !strings.EqualFold(estimate.TxHash, expectedHash) {
		return fmt.Errorf("estimated transaction hash %s differs from approved hash %s", estimate.TxHash, expectedHash)
	}
	if estimate.TxFee != expectedFee {
		return fmt.Errorf("estimated transaction fee %s differs from approved fee %s", estimate.TxFee, expectedFee)
	}
	return nil
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func replicaAPIKeys(
	endpoints, keyEnvironments []string,
	fallback string,
	lookup func(string) (string, bool),
	unset func(string) error,
) ([]string, error) {
	fallback = strings.TrimSpace(fallback)
	if len(endpoints) == 0 {
		if len(keyEnvironments) > 0 {
			return nil, errors.New("replica API-key flags require --verify-rpc")
		}
		return []string{}, nil
	}
	if len(keyEnvironments) > 0 {
		if len(keyEnvironments) != len(endpoints) {
			return nil, errors.New("repeat --verify-api-key-env exactly once for each --verify-rpc")
		}
		keys := make([]string, len(keyEnvironments))
		for index, name := range keyEnvironments {
			value, exists := lookup(name)
			if !exists || strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("replica API-key environment %s is unset or empty", name)
			}
			if err := unset(name); err != nil {
				return nil, fmt.Errorf("remove replica API-key environment %s before child processes: %w", name, err)
			}
			keys[index] = value
		}
		return keys, nil
	}
	if len(endpoints) == 1 {
		return []string{fallback}, nil
	}
	return nil, errors.New("multiple --verify-rpc endpoints require one repeated --verify-api-key-env per endpoint; a single IDENA_VERIFY_API_KEY is ambiguous")
}

type checkpointReplicaVerifier interface {
	VerifyCheckpointReplica(context.Context, protocol.CheckpointInput, uint64) (idena.ChainVerification, error)
}

func verifyCheckpointReplicas(ctx context.Context, replicas []checkpointReplicaVerifier, input protocol.CheckpointInput, maxScan uint64) error {
	if err := protocol.ValidateCheckpointInputPolicy(input); err != nil {
		return err
	}
	for index, replica := range replicas {
		if _, err := replica.VerifyCheckpointReplica(ctx, input, maxScan); err != nil {
			return fmt.Errorf("replica checkpoint verification %d: %w", index+1, err)
		}
	}
	return nil
}

func defaultRadHome() string {
	if value := os.Getenv("RAD_HOME"); value != "" {
		return value
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".radicle")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func resolveSecretEnvironment(name string) (string, error) {
	return resolveSecretEnvironmentWith(name, os.LookupEnv, os.Unsetenv)
}

func resolveSecretEnvironmentWith(
	name string,
	lookup func(string) (string, bool),
	unset func(string) error,
) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	for index, character := range name {
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return "", fmt.Errorf("invalid secret environment variable name %q", name)
	}
	value, exists := lookup(name)
	if !exists {
		return "", nil
	}
	if err := unset(name); err != nil {
		return "", fmt.Errorf("remove secret environment %s before child processes: %w", name, err)
	}
	return value, nil
}

func printUsage(writer io.Writer) {
	fmt.Fprint(writer, `Usage: forge <command> [flags]

Commands:
  demo      Create a deterministic checkpoint UI fixture
  scan      Scan native Idena blocks and historical identity proofs
  reduce    Reduce checkpoint input to canonical repository heads
  verify    Replay a checkpoint and compare it with a saved result
  replay    Apply a sequence of checkpoints and carry canonical heads
  serve     Preview a checkpoint in the browser UI
  export-ui Render one self-contained checkpoint preview for Idena IPFS
  share-ui  Pin the static preview through the node and emit an idena.social plan
  apply     Materialise the governance ref in Radicle storage
  restore   Restore anchored Radicle storage bundles from Idena IPFS
  retain    Pin checkpoint content without expiry for long-lived mirroring
  prune     Preview or apply verified repository deletion after the grace epoch
  gc        Remove expired lease-bound content at the canonical current epoch
  action    Sign an action through Idena dna_sign
  anchor    Package an existing Radicle COB action into an Idena anchor
  publish   Pin an action in IPFS and prepare or send its inline Idena announcement
  mirror    Reproduce and optionally pin an existing publication through this node
  verify-mirror Verify the Idena identity signature on a mirror receipt
  version   Print the version

Only publish can send a chain transaction, and it requires the approved transaction hash and fee.
Commands that invoke Radicle require the reviewed executable digest in RAD_BIN_SHA256.
`)
}
