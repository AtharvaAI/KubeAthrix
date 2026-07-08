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
