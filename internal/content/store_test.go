package content

import (
	"fmt"
	"sync"
	"testing"
)

func TestPinLeaseAndGarbageCollection(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := store.Put([]byte("published in epoch 9"), 11)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Has(cid) {
		t.Fatal("content missing before retention boundary")
	}
	removed, err := store.CollectGarbage(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 || !store.Has(cid) {
		t.Fatal("content removed during the following epoch")
	}
	removed, err = store.CollectGarbage(11)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || store.Has(cid) {
		t.Fatal("content not removed at end of retention lease")
	}
}

func TestContentIsAddressedAndVerified(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := store.PutUnpinned([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(cid)
	if err != nil || string(data) != "one" {
		t.Fatalf("get: %q, %v", data, err)
	}
}

func TestForeverPinSurvivesGarbageCollection(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := store.PutUnpinned([]byte("canonical history"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinForever(cid); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectGarbage(65535); err != nil {
		t.Fatal(err)
	}
	if !store.Has(cid) {
		t.Fatal("forever pin was collected")
	}
}

func TestRepositoryPruneWaitsOneEpochAndPreservesSharedContent(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exclusive, err := store.PutUnpinned([]byte("exclusive"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := store.PutUnpinned([]byte("shared"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinRepository(exclusive, "rad:zRepoOne"); err != nil {
		t.Fatal(err)
	}
	if err := store.PinRepository(shared, "rad:zRepoOne"); err != nil {
		t.Fatal(err)
	}
	if err := store.PinRepository(shared, "rad:zRepoTwo"); err != nil {
		t.Fatal(err)
	}

	removed, err := store.PruneRepository("rad:zRepoOne", 11, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 || !store.Has(exclusive) || !store.Has(shared) {
		t.Fatal("repository content was pruned during the grace epoch")
	}

	removed, err = store.PruneRepository("rad:zRepoOne", 12, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != exclusive {
		t.Fatalf("removed = %v, want only %s", removed, exclusive)
	}
	if store.Has(exclusive) || !store.Has(shared) {
		t.Fatal("repository-specific prune did not preserve shared content")
	}
}

func TestIndependentStoreHandlesSerializePinUpdates(t *testing.T) {
	root := t.TempDir()
	first, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	stores := []*Store{first, second}
	const objects = 40
	errorsByWorker := make(chan error, objects)
	var workers sync.WaitGroup
	for index := 0; index < objects; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			_, err := stores[index%len(stores)].Put([]byte(fmt.Sprintf("object-%d", index)), 9)
			errorsByWorker <- err
		}(index)
	}
	workers.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	pins, err := first.Pins()
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != objects {
		t.Fatalf("pin index lost concurrent updates: got %d, want %d", len(pins), objects)
	}
}
