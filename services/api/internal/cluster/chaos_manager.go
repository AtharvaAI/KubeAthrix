package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/atharvaai/kubeathrix/services/api/internal/core"
	"github.com/atharvaai/kubeathrix/services/api/internal/store"
	"github.com/google/uuid"
)

const (
	chaosApprovalTTL     = 15 * time.Minute
	chaosInjectionWindow = 30 * time.Second
	chaosCleanupGrace    = 30 * time.Second
	chaosRecoveryWindow  = 2 * time.Minute
	chaosPollInterval    = 5 * time.Second
	chaosMaxAttempts     = 3
)

type ChaosManager struct {
	repository       store.Repository
	runner           *ChaosRunner
	executionEnabled bool
	now              func() time.Time
	logger           *slog.Logger
	pollInterval     time.Duration
}

func NewChaosManager(repository store.Repository, runner *ChaosRunner, executionEnabled bool, logger *slog.Logger) *ChaosManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &ChaosManager{repository: repository, runner: runner, executionEnabled: executionEnabled, now: time.Now, logger: logger, pollInterval: chaosPollInterval}
}

func (m *ChaosManager) Request(ctx context.Context, experimentID, manifest, actor string) (core.ChaosExperimentRun, error) {
	if m.runner == nil {
		return core.ChaosExperimentRun{}, fmt.Errorf("chaos runner is unavailable")
	}
	run, err := m.runner.Preflight(ctx, experimentID, manifest, m.executionEnabled)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	now := m.now().UTC()
	run.ID = "chaos-run-" + uuid.NewString()
	run.RequestedBy = actor
	run.CreatedAt, run.UpdatedAt = now, now
	action := "chaos.preflight.validated"
	if m.executionEnabled {
		run.Status = core.ChaosPendingApproval
		run.Message = "bounded preflight passed; explicit approval by a different principal is required before execution"
		expires := now.Add(chaosApprovalTTL)
		run.ApprovalExpiresAt = &expires
		action = "chaos.approval.requested"
	}
	return m.repository.CreateChaosRun(ctx, run, actor, action)
}

func (m *ChaosManager) Health(ctx context.Context) error {
	if !m.executionEnabled {
		return nil
	}
	if m.runner == nil {
		return fmt.Errorf("chaos runner is unavailable")
	}
	return m.runner.Health(ctx)
}

func (m *ChaosManager) TargetNamespace(manifest string) (string, error) {
	object, err := decodeChaosObject(manifest)
	if err != nil {
		return "", err
	}
	if object.GetNamespace() == "" {
		return "", fmt.Errorf("chaos manifest must declare metadata.namespace")
	}
	return object.GetNamespace(), nil
}

func (m *ChaosManager) Approve(ctx context.Context, id, actor, reason string) (core.ChaosExperimentRun, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: approval reason is required", store.ErrInvalid)
	}
	run, err := m.repository.GetChaosRun(ctx, id)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if run.Status != core.ChaosPendingApproval {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos run is %s, not pending approval", store.ErrConflict, run.Status)
	}
	if run.ApprovalExpiresAt != nil && !m.now().UTC().Before(*run.ApprovalExpiresAt) {
		if _, expireErr := m.expire(ctx, run); expireErr != nil {
			return core.ChaosExperimentRun{}, expireErr
		}
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos approval expired", store.ErrConflict)
	}
	if actor == run.RequestedBy {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: requester cannot approve their own chaos run", store.ErrInvalid)
	}
	run.Status = core.ChaosApproved
	run.ApprovedBy, run.ApprovalReason = actor, reason
	run.Message = "chaos run approved; execution remains a separate explicit request"
	run.UpdatedAt = m.now().UTC()
	return m.repository.UpdateChaosRun(ctx, run, run.Version, actor, "chaos.approved")
}

func (m *ChaosManager) Reject(ctx context.Context, id, actor, reason string) (core.ChaosExperimentRun, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: rejection reason is required", store.ErrInvalid)
	}
	run, err := m.repository.GetChaosRun(ctx, id)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if run.Status != core.ChaosPendingApproval {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos run is %s, not pending approval", store.ErrConflict, run.Status)
	}
	if run.ApprovalExpiresAt != nil && !m.now().UTC().Before(*run.ApprovalExpiresAt) {
		if _, expireErr := m.expire(ctx, run); expireErr != nil {
			return core.ChaosExperimentRun{}, expireErr
		}
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos approval expired", store.ErrConflict)
	}
	if actor == run.RequestedBy {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: requester cannot reject their own chaos run", store.ErrInvalid)
	}
	now := m.now().UTC()
	run.Status, run.ApprovedBy, run.ApprovalReason = core.ChaosRejected, actor, reason
	run.Message, run.UpdatedAt, run.FinishedAt = "chaos run rejected; no resource was created", now, &now
	return m.repository.UpdateChaosRun(ctx, run, run.Version, actor, "chaos.rejected")
}

func (m *ChaosManager) Execute(ctx context.Context, id, actor string) (core.ChaosExperimentRun, error) {
	if !m.executionEnabled {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos execution is disabled", store.ErrInvalid)
	}
	run, err := m.repository.GetChaosRun(ctx, id)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if run.Status != core.ChaosApproved {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos run is %s, not approved", store.ErrConflict, run.Status)
	}
	if run.ApprovalExpiresAt != nil && !m.now().UTC().Before(*run.ApprovalExpiresAt) {
		if _, expireErr := m.expire(ctx, run); expireErr != nil {
			return core.ChaosExperimentRun{}, expireErr
		}
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: approved chaos run expired before execution", store.ErrConflict)
	}
	run.Status, run.Message, run.UpdatedAt = core.ChaosExecutionRequested, "chaos execution requested; Kubernetes creation has not yet been acknowledged", m.now().UTC()
	run, err = m.repository.UpdateChaosRun(ctx, run, run.Version, actor, "chaos.execution.requested")
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if err := m.reconcileOne(ctx, run); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	return m.repository.GetChaosRun(ctx, id)
}

func (m *ChaosManager) Abort(ctx context.Context, id, actor, reason string) (core.ChaosExperimentRun, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: abort reason is required", store.ErrInvalid)
	}
	run, err := m.repository.GetChaosRun(ctx, id)
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	switch run.Status {
	case core.ChaosPendingApproval, core.ChaosApproved, core.ChaosExecutionRequested, core.ChaosRunning, core.ChaosCleanupRequested, core.ChaosVerifying:
	default:
		return core.ChaosExperimentRun{}, fmt.Errorf("%w: chaos run in state %s cannot be aborted", store.ErrConflict, run.Status)
	}
	now := m.now().UTC()
	if run.Status == core.ChaosPendingApproval || run.Status == core.ChaosApproved {
		run.Status, run.AbortedBy = core.ChaosAborted, actor
		run.Message, run.UpdatedAt, run.FinishedAt = "approved chaos run aborted before resource creation: "+reason, now, &now
		return m.repository.UpdateChaosRun(ctx, run, run.Version, actor, "chaos.aborted")
	}
	run.Status, run.AbortedBy = core.ChaosAbortRequested, actor
	run.Message, run.UpdatedAt = "chaos abort requested; deleting the owned resource: "+reason, now
	recovery := now.Add(chaosCleanupGrace + chaosRecoveryWindow)
	run.RecoveryDeadline = &recovery
	run, err = m.repository.UpdateChaosRun(ctx, run, run.Version, actor, "chaos.abort.requested")
	if err != nil {
		return core.ChaosExperimentRun{}, err
	}
	if err := m.reconcileOne(ctx, run); err != nil {
		return core.ChaosExperimentRun{}, err
	}
	return m.repository.GetChaosRun(ctx, id)
}

func (m *ChaosManager) Get(ctx context.Context, id string) (core.ChaosExperimentRun, error) {
	run, err := m.repository.GetChaosRun(ctx, id)
	if err == nil && (chaosActive(run.Status) || run.Status == core.ChaosPendingApproval) {
		if reconcileErr := m.reconcileOne(ctx, run); reconcileErr != nil {
			return run, reconcileErr
		}
		return m.repository.GetChaosRun(ctx, id)
	}
	return run, err
}

func (m *ChaosManager) List(ctx context.Context) ([]core.ChaosExperimentRun, error) {
	return m.repository.ListChaosRuns(ctx)
}

func (m *ChaosManager) StartReconciler(ctx context.Context) {
	go func() {
		m.reconcileAll(ctx)
		ticker := time.NewTicker(m.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.reconcileAll(ctx)
			}
		}
	}()
}

func (m *ChaosManager) reconcileAll(ctx context.Context) {
	runs, err := m.repository.ListChaosRuns(ctx)
	if err != nil {
		m.logger.Error("list chaos runs for reconciliation", "error", err)
		return
	}
	for _, run := range runs {
		if !chaosActive(run.Status) && run.Status != core.ChaosPendingApproval {
			continue
		}
		if err := m.reconcileOne(ctx, run); err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, context.Canceled) {
			m.logger.Error("reconcile chaos run", "run_id", run.ID, "status", run.Status, "error", err)
		}
	}
}

func (m *ChaosManager) reconcileOne(ctx context.Context, run core.ChaosExperimentRun) error {
	now := m.now().UTC()
	if run.Status == core.ChaosPendingApproval && run.ApprovalExpiresAt != nil && !now.Before(*run.ApprovalExpiresAt) {
		_, err := m.expire(ctx, run)
		return err
	}
	switch run.Status {
	case core.ChaosExecutionRequested:
		exists, err := m.runner.Exists(ctx, run)
		if err != nil {
			return err
		}
		if !exists && run.InjectionDeadline != nil {
			recovery := now.Add(chaosRecoveryWindow)
			run.Status, run.FailureReason, run.Message = core.ChaosVerifying, "owned chaos resource disappeared before injection was proven", "chaos resource disappeared before AllInjected=True; verifying target recovery"
			run.RecoveryDeadline, run.UpdatedAt = &recovery, now
			_, updateErr := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.recovery.requested")
			return updateErr
		}
		if !exists {
			if err := m.runner.Start(ctx, run); err != nil {
				run.AttemptCount++
				run.Message, run.UpdatedAt = fmt.Sprintf("chaos creation attempt %d failed: %v", run.AttemptCount, err), now
				action := "chaos.execution.retry"
				if run.AttemptCount >= chaosMaxAttempts {
					run.Status, run.FinishedAt = core.ChaosFailed, &now
					action = "chaos.failed"
				}
				_, updateErr := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", action)
				return updateErr
			}
			injectionDeadline := now.Add(chaosInjectionWindow)
			run.Message, run.InjectionDeadline, run.UpdatedAt = "Kubernetes acknowledged the owned chaos resource; awaiting Chaos Mesh AllInjected=True", &injectionDeadline, now
			_, updateErr := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.resource.created")
			return updateErr
		}
		if run.InjectionDeadline == nil {
			injectionDeadline := now.Add(chaosInjectionWindow)
			run.Message, run.InjectionDeadline, run.UpdatedAt = "recovered an owned chaos resource after restart; awaiting Chaos Mesh AllInjected=True", &injectionDeadline, now
			_, updateErr := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.resource.recovered")
			return updateErr
		}
		observation, err := m.runner.Observe(ctx, run)
		if err != nil {
			return err
		}
		if !observation.AllInjected {
			if now.Before(*run.InjectionDeadline) {
				if observation.Message != "" && observation.Message != run.Message {
					run.Message, run.UpdatedAt = observation.Message, now
					_, updateErr := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.injection.pending")
					return updateErr
				}
				return nil
			}
			cleanup := now.Add(chaosCleanupGrace)
			recovery := cleanup.Add(chaosRecoveryWindow)
			failureReason := "Chaos Mesh did not report AllInjected=True before the injection deadline"
			if observation.Failed && observation.Message != "" {
				failureReason = observation.Message
			}
			run.Status, run.FailureReason = core.ChaosCleanupRequested, failureReason
			run.Message, run.CleanupDeadline, run.RecoveryDeadline, run.UpdatedAt = run.FailureReason+"; cleanup requested", &cleanup, &recovery, now
			_, updateErr := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.cleanup.requested")
			return updateErr
		}
		cleanup := now.Add(time.Duration(run.DurationSeconds)*time.Second + chaosCleanupGrace)
		recovery := cleanup.Add(chaosRecoveryWindow)
		run.Status, run.Message, run.StartedAt, run.CleanupDeadline, run.RecoveryDeadline, run.UpdatedAt = core.ChaosRunning, observation.Message+"; bounded execution is running", &now, &cleanup, &recovery, now
		_, err = m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.execution.started")
		return err
	case core.ChaosRunning:
		if run.StartedAt == nil {
			run.Status, run.Message, run.UpdatedAt, run.FinishedAt = core.ChaosFailed, "running chaos record has no acknowledged start time", now, &now
			_, err := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.failed")
			return err
		}
		exists, err := m.runner.Exists(ctx, run)
		if err != nil {
			return err
		}
		executionEnd := run.StartedAt.Add(time.Duration(run.DurationSeconds) * time.Second)
		if exists && now.Before(executionEnd) {
			return nil
		}
		if !exists && now.Before(executionEnd) {
			recovery := now.Add(chaosRecoveryWindow)
			run.Status, run.FailureReason, run.Message = core.ChaosVerifying, "owned chaos resource disappeared before the bounded duration elapsed", "chaos resource disappeared early; verifying target recovery"
			run.RecoveryDeadline, run.UpdatedAt = &recovery, now
			_, err := m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.recovery.requested")
			return err
		}
		run.Status, run.Message, run.UpdatedAt = core.ChaosCleanupRequested, "execution duration elapsed; cleanup requested", now
		run, err = m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.cleanup.requested")
		if err != nil {
			return err
		}
		fallthrough
	case core.ChaosCleanupRequested:
		if err := m.runner.Delete(ctx, run); err != nil {
			return err
		}
		exists, err := m.runner.Exists(ctx, run)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		run.Status, run.Message, run.UpdatedAt = core.ChaosVerifying, "owned chaos resource deleted; verifying workload recovery", now
		_, err = m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.cleanup.completed")
		return err
	case core.ChaosAbortRequested:
		if err := m.runner.Delete(ctx, run); err != nil {
			return err
		}
		exists, err := m.runner.Exists(ctx, run)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		healthy, message, err := m.runner.VerifyRecovery(ctx, run)
		if err != nil {
			return err
		}
		if healthy {
			run.Status, run.RecoveryStatus, run.RecoveryMessage, run.Message, run.UpdatedAt, run.FinishedAt = core.ChaosAborted, "healthy", message, "chaos run aborted; resource deletion and target recovery were verified", now, &now
			_, err = m.repository.UpdateChaosRun(ctx, run, run.Version, run.AbortedBy, "chaos.aborted")
			return err
		}
		if run.RecoveryDeadline != nil && !now.Before(*run.RecoveryDeadline) {
			run.Status, run.RecoveryStatus, run.RecoveryMessage, run.Message, run.UpdatedAt, run.FinishedAt = core.ChaosFailed, "unhealthy", message, "abort cleanup completed but target recovery timed out", now, &now
			_, err = m.repository.UpdateChaosRun(ctx, run, run.Version, run.AbortedBy, "chaos.failed")
			return err
		}
		return nil
	case core.ChaosVerifying:
		exists, err := m.runner.Exists(ctx, run)
		if err != nil {
			return err
		}
		if exists {
			if run.CleanupDeadline != nil && !now.Before(*run.CleanupDeadline) {
				return m.runner.Delete(ctx, run)
			}
			return nil
		}
		healthy, message, err := m.runner.VerifyRecovery(ctx, run)
		if err != nil {
			return err
		}
		run.RecoveryMessage, run.UpdatedAt = message, now
		if healthy {
			action := "chaos.succeeded"
			run.Status, run.RecoveryStatus, run.FinishedAt = core.ChaosSucceeded, "healthy", &now
			run.Message = "chaos resource cleaned up and target recovery was verified"
			if run.FailureReason != "" {
				run.Status, action = core.ChaosFailed, "chaos.failed"
				run.Message = run.FailureReason + "; resource cleanup and target recovery were verified"
			}
			_, err = m.repository.UpdateChaosRun(ctx, run, run.Version, "system", action)
			return err
		}
		if run.RecoveryDeadline != nil && !now.Before(*run.RecoveryDeadline) {
			run.Status, run.RecoveryStatus, run.Message, run.FinishedAt = core.ChaosFailed, "unhealthy", "target recovery verification timed out", &now
			_, err = m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.failed")
			return err
		}
	}
	return nil
}

func (m *ChaosManager) expire(ctx context.Context, run core.ChaosExperimentRun) (core.ChaosExperimentRun, error) {
	now := m.now().UTC()
	run.Status, run.Message, run.UpdatedAt, run.FinishedAt = core.ChaosExpired, "chaos approval expired; no resource was created", now, &now
	return m.repository.UpdateChaosRun(ctx, run, run.Version, "system", "chaos.approval.expired")
}

func chaosActive(status string) bool {
	switch status {
	case core.ChaosExecutionRequested, core.ChaosRunning, core.ChaosCleanupRequested, core.ChaosAbortRequested, core.ChaosVerifying:
		return true
	default:
		return false
	}
}
