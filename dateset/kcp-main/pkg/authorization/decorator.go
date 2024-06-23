/*
Copyright 2022 The KCP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authorization

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	kaudit "k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

const (
	DecisionNoOpinion = "NoOpinion"
	DecisionAllowed   = "Allowed"
	DecisionDenied    = "Denied"
)

const (
	auditDecision = "decision"
	auditReason   = "reason"
)

type Decorator struct {
	target authorizer.Authorizer
	key    string
}

// NewDecorator returns a new authorizer which is associated with the given key.
// The prefix key must not contain a slash `/`.
// Decorating functions are applied in the order they have been invoked.
func NewDecorator(key string, target authorizer.Authorizer) *Decorator {
	if strings.Contains(key, "/") {
		panic(fmt.Sprintf("audit prefix must not contain a slash: %q", key))
	}
	return &Decorator{target: target, key: key}
}

// AddAuditLogging logs every decision of the target authorizer for the given audit prefix key
// if the decision is not allowed.
// All authorizer decisions are being logged in the audit log if the context was set using WithAuditLogging.
// This prevents double audit log entries by multiple invocations of the authorizer chain.
func (d *Decorator) AddAuditLogging() *Decorator {
	target := d.target
	d.target = authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		dec, reason, err := target.Authorize(ctx, attr)

		auditReasonMsg := reason
		if err != nil {
			auditReasonMsg = fmt.Sprintf("reason: %v, error: %v", reason, err)
		}

		if domain := ctx.Value(auditDomainKey); domain != nil && domain != "" {
			kaudit.AddAuditAnnotations(
				ctx,
				fmt.Sprintf("%s/%s-%s", domain, d.key, auditDecision), decisionString(dec),
				fmt.Sprintf("%s/%s-%s", domain, d.key, auditReason), auditReasonMsg,
			)
		}

		if dec != authorizer.DecisionAllow {
			// Note: this deviates from upstream which doesn't log audit reasons.
			// We should rethink if this should stay.
			logger := klog.FromContext(ctx)
			logger.V(4).Info(auditReasonMsg)
		}

		return dec, reason, err
	})
	return d
}

// AddAnonymization anonymizes authorization decisions,
// returning "access granted" reason in case of an allow decision and "access denied" reason otherwise to the next decoration.
// Previous decorations are not anonymized.
func (d *Decorator) AddAnonymization() *Decorator {
	target := d.target
	d.target = authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		dec, reason, err := target.Authorize(ctx, attr)

		switch dec {
		case authorizer.DecisionAllow:
			reason = "access granted"
		case authorizer.DecisionDeny:
			reason = "access denied"
		case authorizer.DecisionNoOpinion:
			reason = "access denied"
		}

		return dec, reason, err
	})
	return d
}

// AddReasonAnnotation adds the authorizer key as a prefix to the authorizer reason and passes that to the next decoration.
// This is useful where AddAnonymization was used as a decoration, but we still want to identify the authorizer in audit logs
// when this decorator is passed as a delegate in an authorizer chains.
func (d *Decorator) AddReasonAnnotation() *Decorator {
	target := d.target
	d.target = authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		dec, reason, err := target.Authorize(ctx, attr)
		return dec, d.key + ": " + reason, err
	})
	return d
}

func (d *Decorator) Authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	return d.target.Authorize(ctx, attr)
}

// decisionString returns a kcp-opinionated string representation of an authorizer decision for audit logging.
func decisionString(dec authorizer.Decision) string {
	switch dec {
	case authorizer.DecisionNoOpinion:
		return DecisionNoOpinion
	case authorizer.DecisionAllow:
		return DecisionAllowed
	case authorizer.DecisionDeny:
		return DecisionDenied
	}
	return ""
}

// DelegateAuthorization delegates authorization to the given delegate authorizer
// and prefixes the given reason with the reason after the given delegate authorizer executed.
func DelegateAuthorization(delegationReason string, delegate authorizer.Authorizer) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		dec, _, err := delegate.Authorize(ctx, attr)
		return dec, "delegating due to " + delegationReason, err
	})
}

type auditLoggingDomainType int

const (
	auditDomainKey auditLoggingDomainType = iota
)

// WithAuditLogging stores the given domain in the context to be used when logging
// audit events in the given authorizer chain. The annotations will have the format
// <prefix>.<domain>/<key>. If that context is not set, audit logging is skipped.
// Note that this is only respected by authorizers that have been decorated using Decorator.AddAuditLogging.
func WithAuditLogging(annotationDomain string, delegate authorizer.Authorizer) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		ctx = context.WithValue(ctx, auditDomainKey, annotationDomain)
		return delegate.Authorize(ctx, a)
	})
}

func WithSubjectAccessReviewAuditAnnotations(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ri, ok := genericapirequest.RequestInfoFrom(r.Context())
		if !ok {
			responsewriters.InternalError(w, r, fmt.Errorf("cannot get request info"))
			return
		}
		if !ri.IsResourceRequest || ri.APIGroup != authorizationv1.GroupName || ri.Resource != "subjectaccessreviews" || ri.Verb != "create" {
			handler.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), auditDomainKey, "sar.auth.kcp.io")
		r = r.WithContext(ctx)

		handler.ServeHTTP(w, r)
	})
}
