package sql

import (
	"github.com/Masterminds/squirrel"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/tz"
)

func (d *SqlDb) CreateProject(project db.Project) (newProject db.Project, err error) {
	project.Created = tz.Now()

	insertId, err := d.insert(
		"id",
		"insert into project(name, created, type, alert, alert_chat, max_parallel_tasks, tenant_id, deployment_zone_id) values (?, ?, ?, ?, ?, ?, ?, ?)",
		project.Name, project.Created, project.Type, project.Alert, project.AlertChat, project.MaxParallelTasks,
		project.TenantID, project.DeploymentZoneID)

	if err != nil {
		return
	}

	newProject = project
	newProject.ID = insertId
	return
}

func (d *SqlDb) GetAllProjects() (projects []db.Project, err error) {
	query, args, err := squirrel.Select("p.*").
		From("project as p").
		OrderBy("p.name").
		Limit(200).
		ToSql()

	if err != nil {
		return
	}

	_, err = d.selectAll(&projects, query, args...)

	return
}

func (d *SqlDb) GetProjects(userID int) (projects []db.Project, err error) {
	query, args, err := squirrel.Select("p.*").
		From("project as p").
		Join("project__user as pu on pu.project_id=p.id").
		Where("pu.user_id=?", userID).
		OrderBy("p.name").
		Limit(200).
		ToSql()

	if err != nil {
		return
	}

	_, err = d.selectAll(&projects, query, args...)

	return
}

func (d *SqlDb) GetProject(projectID int) (project db.Project, err error) {
	query, args, err := squirrel.Select("p.*").
		From("project as p").
		Where("p.id=?", projectID).
		ToSql()

	if err != nil {
		return
	}

	err = d.selectOne(&project, query, args...)

	return
}

func (d *SqlDb) DeleteProject(projectID int) error {

	//tpls, err := d.GetTemplates(projectID, db.TemplateFilter{}, db.RetrieveQueryParams{})
	//
	//if err != nil {
	//	return err
	//}
	// TODO: sort projects

	tx, err := d.Sql().Begin()

	if err != nil {
		return err
	}

	statements := []string{
		"update project__template set build_template_id = null where project_id=?",
		"delete from project__template where project_id=?",
		"delete from project__user where project_id=?",
		"delete from project__repository where project_id=?",
		"delete from project__inventory where project_id=?",
		"delete from access_key where project_id=?",
		"delete from project where id=?",
	}

	for _, statement := range statements {
		_, err = tx.Exec(d.PrepareQuery(statement), projectID)

		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (d *SqlDb) UpdateProject(project db.Project) error {
	_, err := d.exec(
		"update project set name=?, alert=?, alert_chat=?, max_parallel_tasks=?, tenant_id=?, deployment_zone_id=? where id=?",
		project.Name,
		project.Alert,
		project.AlertChat,
		project.MaxParallelTasks,
		project.TenantID,
		project.DeploymentZoneID,
		project.ID)
	return err
}

// GetProjectForTenant returns the project only if its tenant_id matches
// the supplied tenantID. On a cross-tenant read it returns ErrNotFound
// (not 403) so the operator cannot probe for foreign-tenant resource
// existence — per design doc §4.2 + decision 4.
//
// SentraOps fork (R-I.1.c).
func (d *SqlDb) GetProjectForTenant(projectID int, tenantID string) (db.Project, error) {
	project, err := d.GetProject(projectID)
	if err != nil {
		return db.Project{}, err
	}
	if project.TenantID != tenantID {
		return db.Project{}, db.ErrNotFound
	}
	return project, nil
}

// GetProjectsForTenant lists every project whose tenant_id matches
// tenantID, ordered by name. This is the operator-scoped equivalent
// of GetAllProjects; the platform-BE service-to-service path uses
// GetAllProjects (with X-Skip-Tenant-Filter set after mTLS validation).
func (d *SqlDb) GetProjectsForTenant(tenantID string) ([]db.Project, error) {
	query, args, err := squirrel.Select("p.*").
		From("project as p").
		Where("p.tenant_id=?", tenantID).
		OrderBy("p.name").
		Limit(200).
		ToSql()
	if err != nil {
		return nil, err
	}

	var projects []db.Project
	_, err = d.selectAll(&projects, query, args...)
	return projects, err
}

// UpdateProjectForTenant updates the project only if its tenant_id
// matches tenantID. Returns ErrNotFound on cross-tenant write.
func (d *SqlDb) UpdateProjectForTenant(project db.Project, tenantID string) error {
	// Defense in depth: verify the project's tenant before issuing the
	// UPDATE so a cross-tenant attempt cannot succeed even if a handler
	// forgets to set the right project ID.
	if _, err := d.GetProjectForTenant(project.ID, tenantID); err != nil {
		return err
	}
	return d.UpdateProject(project)
}

// DeleteProjectForTenant deletes the project only if its tenant_id
// matches tenantID. Returns ErrNotFound on cross-tenant delete.
func (d *SqlDb) DeleteProjectForTenant(projectID int, tenantID string) error {
	if _, err := d.GetProjectForTenant(projectID, tenantID); err != nil {
		return err
	}
	return d.DeleteProject(projectID)
}
