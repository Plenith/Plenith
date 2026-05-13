{{/*
Common helpers shared across Plenith templates.
*/}}

{{- define "plenith.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "plenith.labels" -}}
app.kubernetes.io/name:       {{ .Chart.Name }}
app.kubernetes.io/instance:   {{ .Release.Name }}
app.kubernetes.io/version:    {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart:                {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "plenith.selectorLabels" -}}
app.kubernetes.io/name:     {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Agent environment block — content rotation + LLM endpoint + shared state.
Used by every agent template (bastion/db/api) so all agents agree on
the corp identity for this deployment.
*/}}
{{- define "plenith.agentEnv" -}}
- name: PLENITH_DEPLOYMENT_ID
  value: {{ .Values.global.deploymentId | quote }}
- name: PLENITH_CONTENT_EPOCH
  value: {{ .Values.global.contentEpoch | quote }}
- name: PLENITH_LLM_URL
  value: {{ .Values.llm.baseUrl | quote }}
- name: PLENITH_LLM_MODEL
  value: {{ .Values.llm.model | quote }}
- name: PLENITH_SHARED_STATE
  value: "/mnt/state"
- name: PLENITH_SSH_PORT
  value: "22"
- name: PLENITH_PROXY_PROTOCOL_PORT
  value: "2200"
{{- end }}

{{/*
Optional pod-level runtimeClassName for gVisor / Kata isolation
(only emitted when explicitly set so empty strings don't break the API).
*/}}
{{- define "plenith.runtimeClass" -}}
{{- if .Values.runtime.runtimeClassName -}}
runtimeClassName: {{ .Values.runtime.runtimeClassName | quote }}
{{- end }}
{{- end }}
