{{- define "kubeathrix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubeathrix.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kubeathrix.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "kubeathrix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kubeathrix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubeathrix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kubeathrix.postgresSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-postgres" (include "kubeathrix.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "kubeathrix.databaseURL" -}}
{{- if .Values.postgres.external -}}
{{- printf "postgres://%s:$(POSTGRES_PASSWORD)@%s:%v/%s?sslmode=require" .Values.postgres.username .Values.postgres.host .Values.postgres.port .Values.postgres.database -}}
{{- else -}}
{{- printf "postgres://%s:$(POSTGRES_PASSWORD)@%s-postgres:%v/%s?sslmode=disable" .Values.postgres.username (include "kubeathrix.fullname" .) .Values.postgres.port .Values.postgres.database -}}
{{- end -}}
{{- end -}}

{{- define "kubeathrix.validateManagedExternalResources" -}}
{{- $config := .Values.api.managedExternalResources | default dict -}}
{{- $allowlist := $config.allowlist | default (list) -}}
{{- if and (default false $config.enabled) (eq (len $allowlist) 0) -}}
{{- fail "api.managedExternalResources.enabled=true requires at least one explicit allowlist entry" -}}
{{- end -}}
{{- range $index, $entry := $allowlist -}}
{{- $position := $index -}}
{{- if not (kindIs "map" $entry) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d] must be an object" $position) -}}
{{- end -}}
{{- if not (kindIs "string" $entry.apiGroup) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].apiGroup must be a string" $position) -}}
{{- end -}}
{{- if or (empty $entry.apiGroup) (eq (lower $entry.apiGroup) "core") -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].apiGroup must name a non-core API group" $position) -}}
{{- end -}}
{{- if contains "*" $entry.apiGroup -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].apiGroup must not contain a wildcard" $position) -}}
{{- end -}}
{{- if not (kindIs "string" $entry.version) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].version must be a string" $position) -}}
{{- end -}}
{{- if empty $entry.version -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].version is required" $position) -}}
{{- end -}}
{{- if contains "*" $entry.version -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].version must not contain a wildcard" $position) -}}
{{- end -}}
{{- if or (not (hasKey $entry "resources")) (not (kindIs "slice" $entry.resources)) (eq (len $entry.resources) 0) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].resources must contain at least one explicit resource plural" $position) -}}
{{- end -}}
{{- range $resource := $entry.resources -}}
{{- if not (kindIs "string" $resource) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].resources entries must be strings" $position) -}}
{{- end -}}
{{- if or (empty $resource) (contains "*" $resource) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].resources must not contain empty values or wildcards" $position) -}}
{{- end -}}
{{- end -}}
{{- if not (hasKey $entry "namespaced") -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].namespaced is required" $position) -}}
{{- end -}}
{{- if not (kindIs "bool" $entry.namespaced) -}}
{{- fail (printf "api.managedExternalResources.allowlist[%d].namespaced must be true or false" $position) -}}
{{- end -}}
{{- end -}}
{{- end -}}
