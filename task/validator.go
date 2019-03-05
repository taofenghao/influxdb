package task

import (
	"context"
	"errors"
	"fmt"
	"github.com/opentracing/opentracing-go"
	"time"

	"github.com/influxdata/flux"
	platform "github.com/influxdata/influxdb"
	platcontext "github.com/influxdata/influxdb/context"
	"github.com/influxdata/influxdb/query"
)

type authError struct {
	error
	perm platform.Permission
	auth platform.Authorizer
}

func (ae *authError) AuthzError() error {
	return fmt.Errorf("permission failed for auth (%s): %s", ae.auth.Identifier().String(), ae.perm.String())
}

var ErrFailedPermission = errors.New("unauthorized")

type taskServiceValidator struct {
	platform.TaskService
	preAuth query.PreAuthorizer
}

func NewValidator(ts platform.TaskService, bs platform.BucketService) platform.TaskService {
	return &taskServiceValidator{
		TaskService: ts,
		preAuth:     query.NewPreAuthorizer(bs),
	}
}

func (ts *taskServiceValidator) FindTaskByID(ctx context.Context, id platform.ID) (*platform.Task, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.FindTaskByID")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, id)
	if err != nil {
		return nil, err
	}

	perm, err := platform.NewPermissionAtID(id, platform.ReadAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return nil, err
	}

	if err := validatePermission(ctx, *perm); err != nil {
		return nil, err
	}

	return task, nil
}

func (ts *taskServiceValidator) FindTasks(ctx context.Context, filter platform.TaskFilter) ([]*platform.Task, int, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.FindTasks")
	defer span.Finish()

	// First, get the tasks in the organization, without authentication.
	unauthenticatedTasks, _, err := ts.TaskService.FindTasks(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	// Then, filter down to what the user is allowed to see.
	tasks := make([]*platform.Task, 0, len(unauthenticatedTasks))
	for _, t := range unauthenticatedTasks {
		perm, err := platform.NewPermissionAtID(t.ID, platform.ReadAction, platform.TasksResourceType, t.OrganizationID)
		if err != nil {
			continue
		}

		if err := validatePermission(ctx, *perm); err != nil {
			continue
		}

		// Allowed to read it.
		tasks = append(tasks, t)
	}

	return tasks, len(tasks), nil
}

func (ts *taskServiceValidator) CreateTask(ctx context.Context, t platform.TaskCreate) (*platform.Task, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.CreateTask")
	defer span.Finish()

	p, err := platform.NewPermission(platform.WriteAction, platform.TasksResourceType, t.OrganizationID)
	if err != nil {
		return nil, err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return nil, err
	}

	if err := validateBucket(ctx, t.Flux, ts.preAuth); err != nil {
		return nil, err
	}

	return ts.TaskService.CreateTask(ctx, t)
}

func (ts *taskServiceValidator) UpdateTask(ctx context.Context, id platform.ID, upd platform.TaskUpdate) (*platform.Task, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.UpdateTask")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, id)
	if err != nil {
		return nil, err
	}

	p, err := platform.NewPermissionAtID(id, platform.WriteAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return nil, err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return nil, err
	}

	if err := validateBucket(ctx, task.Flux, ts.preAuth); err != nil {
		return nil, err
	}

	return ts.TaskService.UpdateTask(ctx, id, upd)
}

func (ts *taskServiceValidator) DeleteTask(ctx context.Context, id platform.ID) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.DeleteTask")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, id)
	if err != nil {
		return err
	}

	p, err := platform.NewPermissionAtID(id, platform.WriteAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return err
	}

	return ts.TaskService.DeleteTask(ctx, id)
}

func (ts *taskServiceValidator) FindLogs(ctx context.Context, filter platform.LogFilter) ([]*platform.Log, int, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.FindLogs")
	defer span.Finish()

	// Look up the task first, through the validator, to ensure we have permission to view the task.
	if _, err := ts.FindTaskByID(ctx, filter.Task); err != nil {
		return nil, -1, err
	}

	// If we can find the task, we can read its logs.
	return ts.TaskService.FindLogs(ctx, filter)
}

func (ts *taskServiceValidator) FindRuns(ctx context.Context, filter platform.RunFilter) ([]*platform.Run, int, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.FindRuns")
	defer span.Finish()

	// Look up the task first, through the validator, to ensure we have permission to view the task.
	task, err := ts.FindTaskByID(ctx, filter.Task)
	if err != nil {
		return nil, -1, err
	}

	perm, err := platform.NewPermissionAtID(task.ID, platform.ReadAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return nil, -1, err
	}

	if err := validatePermission(ctx, *perm); err != nil {
		return nil, -1, err
	}

	// TODO(lyon): If the user no longer has permission to the organization we might fail or filter here?
	return ts.TaskService.FindRuns(ctx, filter)
}

func (ts *taskServiceValidator) FindRunByID(ctx context.Context, taskID, runID platform.ID) (*platform.Run, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.FindRunByID")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	p, err := platform.NewPermissionAtID(taskID, platform.ReadAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return nil, err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return nil, err
	}

	return ts.TaskService.FindRunByID(ctx, taskID, runID)
}

func (ts *taskServiceValidator) CancelRun(ctx context.Context, taskID, runID platform.ID) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.CancelRun")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, taskID)
	if err != nil {
		return err
	}

	p, err := platform.NewPermissionAtID(taskID, platform.WriteAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return err
	}

	return ts.TaskService.CancelRun(ctx, taskID, runID)
}

func (ts *taskServiceValidator) RetryRun(ctx context.Context, taskID, runID platform.ID) (*platform.Run, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.RetryRun")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	p, err := platform.NewPermissionAtID(taskID, platform.WriteAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return nil, err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return nil, err
	}

	return ts.TaskService.RetryRun(ctx, taskID, runID)
}

func (ts *taskServiceValidator) ForceRun(ctx context.Context, taskID platform.ID, scheduledFor int64) (*platform.Run, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "taskServiceValidator.ForceRun")
	defer span.Finish()

	// Unauthenticated task lookup, to identify the task's organization.
	task, err := ts.TaskService.FindTaskByID(ctx, taskID)
	if err != nil {
		return nil, err
	}

	p, err := platform.NewPermissionAtID(taskID, platform.WriteAction, platform.TasksResourceType, task.OrganizationID)
	if err != nil {
		return nil, err
	}

	if err := validatePermission(ctx, *p); err != nil {
		return nil, err
	}

	return ts.TaskService.ForceRun(ctx, taskID, scheduledFor)
}

func validatePermission(ctx context.Context, perm platform.Permission) error {
	auth, err := platcontext.GetAuthorizer(ctx)
	if err != nil {
		return err
	}

	if !auth.Allowed(perm) {
		return authError{error: ErrFailedPermission, perm: perm, auth: auth}
	}

	return nil
}

func validateBucket(ctx context.Context, script string, preAuth query.PreAuthorizer) error {
	auth, err := platcontext.GetAuthorizer(ctx)
	if err != nil {
		return err
	}

	spec, err := flux.Compile(ctx, script, time.Now())
	if err != nil {
		return platform.NewError(
			platform.WithErrorErr(err),
			platform.WithErrorMsg("Failed to compile flux script."),
			platform.WithErrorCode(platform.EInvalid))
	}

	if err := preAuth.PreAuthorize(ctx, spec, auth); err != nil {
		return platform.NewError(
			platform.WithErrorErr(err),
			platform.WithErrorMsg("Failed to authorize."),
			platform.WithErrorCode(platform.EInvalid))
	}

	return nil
}
