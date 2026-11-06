package content

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const storeVersion = 1

type PinRecord struct {
	CID          string   `json:"cid"`
	UntilEpoch   uint16   `json:"untilEpoch"`
	Forever      bool     `json:"forever,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
}

type pinFile struct {
	Version int         `json:"version"`
	Pins    []PinRecord `json:"pins"`
}

type Store struct {
	root string
	mu   sync.Mutex
}

func (store *Store) lockPins() (func(), error) {
	store.mu.Lock()
	releaseFileLock, err := acquirePinsFileLock(store.root)
	if err != nil {
		store.mu.Unlock()
		return nil, err
	}
	return func() {
		releaseFileLock()
		store.mu.Unlock()
	}, nil
}

func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("content directory is required")
	}
	for _, directory := range []string{root, filepath.Join(root, "objects")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{root: root}, nil
}

func CIDForBytes(data []byte) (string, error) {
	hash, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return "", err
	}
	return cid.NewCidV1(cid.Raw, hash).String(), nil
}

func ValidateCID(value string) error {
	parsed, err := cid.Decode(value)
	if err != nil {
		return fmt.Errorf("invalid CID: %w", err)
	}
	if parsed.Version() != 1 {
		return errors.New("only CIDv1 content references are supported")
	}
	if parsed.Type() != cid.Raw {
		return errors.New("content reference must be a raw-block CID")
	}
	decoded, err := multihash.Decode(parsed.Hash())
	if err != nil {
		return err
	}
	if decoded.Code != multihash.SHA2_256 {
		return errors.New("CID must use SHA2-256")
	}
	return nil
}

func (store *Store) Put(data []byte, pinUntil uint16) (string, error) {
	contentCID, err := CIDForBytes(data)
	if err != nil {
		return "", err
	}
	unlock, err := store.lockPins()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := os.WriteFile(store.objectPath(contentCID), data, 0o644); err != nil {
		return "", err
	}
	pins, err := store.readPins()
	if err != nil {
		return "", err
	}
	updated := false
	for index := range pins {
		if pins[index].CID == contentCID {
			if pinUntil > pins[index].UntilEpoch {
				pins[index].UntilEpoch = pinUntil
				updated = true
			}
			break
		}
	}
	if !containsPin(pins, contentCID) {
		pins = append(pins, PinRecord{CID: contentCID, UntilEpoch: pinUntil})
		updated = true
	}
	if updated {
		if err := store.writePins(pins); err != nil {
			return "", err
		}
	}
	return contentCID, nil
}

func (store *Store) PutUnpinned(data []byte) (string, error) {
	contentCID, err := CIDForBytes(data)
	if err != nil {
		return "", err
	}
	unlock, err := store.lockPins()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := os.WriteFile(store.objectPath(contentCID), data, 0o644); err != nil {
		return "", err
	}
	return contentCID, nil
}

func (store *Store) Get(contentCID string) ([]byte, error) {
	if err := ValidateCID(contentCID); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(store.objectPath(contentCID))
	if err != nil {
		return nil, err
	}
	calculated, err := CIDForBytes(data)
	if err != nil {
		return nil, err
	}
	if calculated != contentCID {
		return nil, errors.New("content hash does not match filename")
	}
	return data, nil
}

func (store *Store) Has(contentCID string) bool {
	_, err := store.Get(contentCID)
	return err == nil
}

func (store *Store) Pin(contentCID string, untilEpoch uint16) error {
	if err := ValidateCID(contentCID); err != nil {
		return err
	}
	unlock, err := store.lockPins()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(store.objectPath(contentCID)); err != nil {
		return errors.New("cannot pin missing content")
	}
	pins, err := store.readPins()
	if err != nil {
		return err
	}
	for index := range pins {
		if pins[index].CID == contentCID {
			if pins[index].Forever {
				return nil
			}
			if untilEpoch > pins[index].UntilEpoch {
				pins[index].UntilEpoch = untilEpoch
			}
			return store.writePins(pins)
		}
	}
	pins = append(pins, PinRecord{CID: contentCID, UntilEpoch: untilEpoch})
	return store.writePins(pins)
}

func (store *Store) PinForever(contentCID string) error {
	if err := ValidateCID(contentCID); err != nil {
		return err
	}
	unlock, err := store.lockPins()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(store.objectPath(contentCID)); err != nil {
		return errors.New("cannot pin missing content")
	}
	pins, err := store.readPins()
	if err != nil {
		return err
	}
	for index := range pins {
		if pins[index].CID == contentCID {
			pins[index].Forever = true
			return store.writePins(pins)
		}
	}
	pins = append(pins, PinRecord{CID: contentCID, Forever: true})
	return store.writePins(pins)
}

func (store *Store) PinRepository(contentCID, repository string) error {
	if err := ValidateCID(contentCID); err != nil {
		return err
	}
	if strings.TrimSpace(repository) == "" {
		return errors.New("repository is required")
	}
	unlock, err := store.lockPins()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(store.objectPath(contentCID)); err != nil {
		return errors.New("cannot pin missing content")
	}
	pins, err := store.readPins()
	if err != nil {
		return err
	}
	for index := range pins {
		if pins[index].CID != contentCID {
			continue
		}
		pins[index].Forever = true
		pins[index].Repositories = appendUnique(pins[index].Repositories, repository)
		return store.writePins(pins)
	}
	pins = append(pins, PinRecord{
		CID:          contentCID,
		Forever:      true,
		Repositories: []string{repository},
	})
	return store.writePins(pins)
}

// PruneRepository removes repository-scoped content only after the final epoch
// of the deletion grace period. Objects still referenced by another repository
// remain pinned.
func (store *Store) PruneRepository(repository string, currentEpoch, eligibleEpoch uint16) ([]string, error) {
	unlock, err := store.lockPins()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if currentEpoch < eligibleEpoch {
		return nil, nil
	}
	pins, err := store.readPins()
	if err != nil {
		return nil, err
	}
	kept := make([]PinRecord, 0, len(pins))
	var removed []string
	for _, pin := range pins {
		index := repositoryIndex(pin.Repositories, repository)
		if index < 0 {
			kept = append(kept, pin)
			continue
		}
		remaining := append([]string(nil), pin.Repositories[:index]...)
		remaining = append(remaining, pin.Repositories[index+1:]...)
		if len(remaining) > 0 {
			pin.Repositories = remaining
			pin.Forever = true
			kept = append(kept, pin)
			continue
		}
		if err := os.Remove(store.objectPath(pin.CID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		removed = append(removed, pin.CID)
	}
	if err := store.writePins(kept); err != nil {
		return nil, err
	}
	return removed, nil
}

func (store *Store) Pins() ([]PinRecord, error) {
	unlock, err := store.lockPins()
	if err != nil {
		return nil, err
	}
	defer unlock()
	pins, err := store.readPins()
	if err != nil {
		return nil, err
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].CID < pins[j].CID })
	return pins, nil
}

func (store *Store) RepositoryObjects(repository string) ([]string, error) {
	unlock, err := store.lockPins()
	if err != nil {
		return nil, err
	}
	defer unlock()
	pins, err := store.readPins()
	if err != nil {
		return nil, err
	}
	var result []string
	for _, pin := range pins {
		if repositoryIndex(pin.Repositories, repository) >= 0 {
			result = append(result, pin.CID)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (store *Store) CollectGarbage(currentEpoch uint16) ([]string, error) {
	unlock, err := store.lockPins()
	if err != nil {
		return nil, err
	}
	defer unlock()
	pins, err := store.readPins()
	if err != nil {
		return nil, err
	}
	kept := make([]PinRecord, 0, len(pins))
	var removed []string
	for _, pin := range pins {
		if pin.Forever || currentEpoch < pin.UntilEpoch {
			kept = append(kept, pin)
			continue
		}
		if err := os.Remove(store.objectPath(pin.CID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		removed = append(removed, pin.CID)
	}
	if err := store.writePins(kept); err != nil {
		return nil, err
	}
	return removed, nil
}

func (store *Store) objectPath(contentCID string) string {
	decoded, err := cid.Decode(contentCID)
	if err != nil {
		return filepath.Join(store.root, "objects", "_invalid_"+strings.ReplaceAll(contentCID, string(filepath.Separator), "_"))
	}
	return filepath.Join(store.root, "objects", decoded.String())
}

func (store *Store) readPins() ([]PinRecord, error) {
	data, err := os.ReadFile(filepath.Join(store.root, "pins.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []PinRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var file pinFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("read pins: %w", err)
	}
	if file.Version != storeVersion {
		return nil, fmt.Errorf("unsupported pin file version %d", file.Version)
	}
	return file.Pins, nil
}

func (store *Store) writePins(pins []PinRecord) error {
	sort.Slice(pins, func(i, j int) bool { return pins[i].CID < pins[j].CID })
	data, err := json.MarshalIndent(pinFile{Version: storeVersion, Pins: pins}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary := filepath.Join(store.root, ".pins.json.tmp")
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(store.root, "pins.json"))
}

func containsPin(pins []PinRecord, contentCID string) bool {
	for _, pin := range pins {
		if pin.CID == contentCID {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	if repositoryIndex(values, value) >= 0 {
		return values
	}
	return append(values, value)
}

func repositoryIndex(values []string, value string) int {
	for index := range values {
		if values[index] == value {
			return index
		}
	}
	return -1
}
