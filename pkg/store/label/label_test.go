package label

import (
	"testing"

	"github.com/opencontainers/selinux/go-selinux"
	"github.com/stretchr/testify/assert"
)

func TestAddThenRemove(t *testing.T) {
	if !selinux.GetEnabled() {
		t.Skip("selinux is not enabled")
	}

	assert := assert.New(t)
	store := NewStore()
	releaseCount := 0
	reserveCount := 0
	store.Releaser = func(label string) {
		assert.Contains(label, ":c1,c2")
		releaseCount++
		assert.Equal(1, releaseCount)
	}
	store.Reserver = func(label string) {
		assert.Contains(label, ":c1,c2")
		reserveCount++
		assert.Equal(1, reserveCount)
	}

	t.Log("should count to two level")
	assert.NoError(store.Reserve("junk:junk:junk:c1,c2"))
	assert.NoError(store.Reserve("junk2:junk2:junk2:c1,c2"))

	t.Log("should have one item")
	assert.Equal(1, len(store.levels))

	t.Log("c1,c2 count should be 2")
	assert.Equal(2, store.levels["c1,c2"])

	store.Release("junk:junk:junk:c1,c2")
	store.Release("junk2:junk2:junk2:c1,c2")

	t.Log("should have 0 items")
	assert.Equal(0, len(store.levels))

	t.Log("should have reserved")
	assert.Equal(1, reserveCount)

	t.Log("should have released")
	assert.Equal(1, releaseCount)
}

func TestJunkData(t *testing.T) {
	if !selinux.GetEnabled() {
		t.Skip("selinux is not enabled")
	}

	assert := assert.New(t)
	store := NewStore()
	releaseCount := 0
	store.Releaser = func(label string) {
		releaseCount++
	}
	reserveCount := 0
	store.Reserver = func(label string) {
		reserveCount++
	}

	t.Log("should ignore empty label")
	assert.NoError(store.Reserve(""))
	assert.Equal(0, len(store.levels))
	store.Release("")
	assert.Equal(0, len(store.levels))
	assert.Equal(0, releaseCount)
	assert.Equal(0, reserveCount)

	t.Log("should fail on bad label")
	assert.Error(store.Reserve("junkjunkjunkc1c2"))
	assert.Equal(0, len(store.levels))
	store.Release("junkjunkjunkc1c2")
	assert.Equal(0, len(store.levels))
	assert.Equal(0, releaseCount)
	assert.Equal(0, reserveCount)

	t.Log("should not release unknown label")
	store.Release("junk2:junk2:junk2:c1,c2")
	assert.Equal(0, len(store.levels))
	assert.Equal(0, releaseCount)
	assert.Equal(0, reserveCount)

	t.Log("should release once even if too many deletes")
	assert.NoError(store.Reserve("junk2:junk2:junk2:c1,c2"))
	assert.Equal(1, len(store.levels))
	assert.Equal(1, store.levels["c1,c2"])
	store.Release("junk2:junk2:junk2:c1,c2")
	store.Release("junk2:junk2:junk2:c1,c2")
	assert.Equal(0, len(store.levels))
	assert.Equal(1, releaseCount)
	assert.Equal(1, reserveCount)
}
