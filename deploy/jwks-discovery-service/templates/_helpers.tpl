{{/*
Common labels.
*/}}
{{- define "jwks-discovery-service.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "jwks-discovery-service.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resource name (release name only – no chart name).
*/}}
{{- define "jwks-discovery-service.fullname" -}}
{{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "jwks-discovery-service.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "jwks-discovery-service.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end }}
