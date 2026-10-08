package sql

import (
	"testing"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration_2_19_14_DataSurvivesRebuild seeds data on the 2.19.12 schema
// and then applies 2.19.14 to ensure the session/task rebuild keeps existing
// rows intact — in particular dropping the old task table must not trigger
// ON DELETE CASCADE into task__output.
func TestMigration_2_19_14_DataSurvivesRebuild(t *testing.T) {
	preRebuild := "2.19.12"
	store := InitConfigCreateTestStoreAt(&preRebuild)

	user, err := store.CreateUserWithoutPassword(db.User{
		Username: "jdoe", Name: "John Doe", Email: "jdoe@example.com",
	})
	require.NoError(t, err)

	now := time.Now()
	session, err := store.CreateSession(db.Session{
		UserID:     user.ID,
		Created:    now,
		LastActive: now,
		UserAgent:  "test",
	})
	require.NoError(t, err)

	// newTemplateTestProject is unusable here: its CreateAccessKey call
	// writes the task_id/expire_at columns which appear only in 2.20.1,
	// so seed the access key with SQL matching the 2.19.12 schema.
	// Same caveat for the project: at v2.19.12 the project table does
	// not yet have tenant_id / deployment_zone_id (those arrive in
	// v2.19.17), so seed the project with raw SQL instead of going
	// through store.CreateProject. We supply every NOT NULL column on
	// the v2.19.12 schema.
	//
	// Same caveat for the task: at v2.19.12 the task table does not
	// yet have claimed_by / claimed_at / result_outcome /
	// result_error_class (those arrive in v2.19.18, R-I.1.d), so seed
	// the task with raw SQL instead of going through
	// store.CreateTask. The gorp mapper auto-includes every db-tagged
	// field on Task — including the post-R-I.1.d claim columns —
	// which would error out against the v2.19.12 schema.
	_, err = store.Sql().Exec(
		"insert into project (name, type, created, max_parallel_tasks) values (?, ?, ?, ?)",
		"proj", "", time.Now().UTC(), 0)
	require.NoError(t, err)
	projectID, err := store.Sql().SelectInt("select id from project where name = ?", "proj")
	require.NoError(t, err)
	projectIDInt := int(projectID)

	keyID, err := store.insert("id",
		"insert into access_key (name, type, project_id) values ('key', 'none', ?)", projectID)
	require.NoError(t, err)

	repo, err := store.CreateRepository(db.Repository{
		ProjectID: projectIDInt,
		Name:      "repo",
		GitURL:    "https://example.com/repo.git",
		GitBranch: "main",
		SSHKeyID:  keyID,
	})
	require.NoError(t, err)

	template, err := store.CreateTemplate(db.Template{
		ProjectID:    projectIDInt,
		RepositoryID: repo.ID,
		Name:         "tpl",
		Playbook:     "site.yml",
	})
	require.NoError(t, err)

	taskID, err := store.insert("id",
		"insert into task (template_id, project_id, status, playbook, environment, message, commit_message, user_id, created) "+
			"values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		template.ID, projectIDInt, "success", "site.yml", "", "", "", user.ID, now.UTC())
	require.NoError(t, err)
	taskIDInt := int(taskID)

	_, err = store.CreateTaskOutput(db.TaskOutput{
		TaskID: taskIDInt,
		Time:   now,
		Output: "ok",
	})
	require.NoError(t, err)

	// Apply the remaining migrations (2.19.14 rebuilds session and task;
	// v2.19.17 adds executor + tenant columns; v2.19.18 adds task claim
	// tracking — R-I.1.d).
	require.NoError(t, db.Migrate(store, nil))

	// The rebuild runs with foreign_keys=OFF, so make sure it left no
	// dangling references behind.
	violations, err := store.Sql().SelectInt("select count(1) from pragma_foreign_key_check")
	require.NoError(t, err)
	assert.Zero(t, violations)

	// Existing rows survived the rebuild.
	survivedSession, err := store.GetSession(user.ID, session.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, survivedSession.UserID)

	survivedTask, err := store.GetTask(projectIDInt, taskIDInt)
	require.NoError(t, err)
	require.NotNil(t, survivedTask.UserID)
	assert.Equal(t, user.ID, *survivedTask.UserID)

	outputs, err := store.GetTaskOutputs(projectIDInt, taskIDInt, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Len(t, outputs, 1)

	// And the rebuilt FKs are in effect: a bare user delete cascades the
	// session and nulls task.user_id.
	_, err = store.exec("delete from `user` where id=?", user.ID)
	require.NoError(t, err)

	_, err = store.GetSession(user.ID, session.ID)
	assert.ErrorIs(t, err, db.ErrNotFound)

	survivedTask, err = store.GetTask(projectIDInt, taskIDInt)
	require.NoError(t, err)
	assert.Nil(t, survivedTask.UserID)
}
