package db

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_Platforms_RoundTrip(t *testing.T) {
	e := Executor{}
	require.NoError(t, e.SetPlatforms([]string{"windows", "linux"}))
	assert.Equal(t, `["windows","linux"]`, e.PlatformsSupportedJSON)
	assert.Equal(t, []string{"windows", "linux"}, e.Platforms())
}

func TestExecutor_Platforms_Empty(t *testing.T) {
	e := Executor{}
	assert.NoError(t, e.SetPlatforms(nil))
	assert.Equal(t, "", e.PlatformsSupportedJSON)
	assert.Nil(t, e.Platforms())

	require.NoError(t, e.SetPlatforms([]string{}))
	assert.Equal(t, "", e.PlatformsSupportedJSON)
}

func TestExecutor_Platforms_CorruptJSON(t *testing.T) {
	// A corrupt JSON value must not panic; it should decode to nil.
	e := Executor{PlatformsSupportedJSON: "{not valid json"}
	assert.Nil(t, e.Platforms())
}

func TestExecutor_SupportsPlatform(t *testing.T) {
	e := Executor{}
	require.NoError(t, e.SetPlatforms([]string{"windows", "linux"}))

	assert.True(t, e.SupportsPlatform("windows"))
	assert.True(t, e.SupportsPlatform("linux"))
	assert.False(t, e.SupportsPlatform("darwin"))
	// Empty platform is treated as "any" (caller passes "" for wildcard).
	assert.True(t, e.SupportsPlatform(""))
}

func TestExecutor_SupportsPlatform_CaseInsensitive(t *testing.T) {
	e := Executor{}
	require.NoError(t, e.SetPlatforms([]string{"windows", "Linux"}))

	assert.True(t, e.SupportsPlatform("WINDOWS"))
	assert.True(t, e.SupportsPlatform("linux"))
	assert.True(t, e.SupportsPlatform("LINUX"))
	assert.False(t, e.SupportsPlatform("darwin"))
}

func TestExecutor_SupportsPlatform_NoPlatformsDeclared(t *testing.T) {
	// An executor that registered without declaring platforms does NOT
	// match any specific platform. The API should always set platforms
	// explicitly, but we still don't want to claim work accidentally.
	e := Executor{}
	assert.False(t, e.SupportsPlatform("windows"))
}

func TestExecutor_IsRevoked(t *testing.T) {
	now := time.Now().UTC()
	active := Executor{}
	assert.False(t, active.IsRevoked())

	revoked := Executor{RevokedAt: &now}
	assert.True(t, revoked.IsRevoked())
}

func TestNewExecutorID_Format(t *testing.T) {
	id, err := NewExecutorID()
	require.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`^EXEC-[0-9A-HJKMNP-TV-Z]{26}$`), id)
}

func TestNewExecutorID_Uniqueness(t *testing.T) {
	// 1000 ids in a tight loop. With 80 random bits the collision
	// probability is astronomically low (~ 2^-80 per id), so this is
	// a sanity test, not a probability assertion.
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id, err := NewExecutorID()
		require.NoError(t, err)
		_, dup := seen[id]
		assert.False(t, dup, "duplicate id at iteration %d: %s", i, id)
		seen[id] = struct{}{}
	}
}
