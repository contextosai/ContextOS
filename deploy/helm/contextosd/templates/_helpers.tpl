{{- define "contextosd.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "contextosd.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "contextosd.labels" -}}
{{ include "contextosd.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "contextosd.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- end -}}

{{/*
The git-sync container for packSync: one-time before contextosd starts (so its pack
directory exists at startup), then continuously beside it.
*/}}
{{- define "contextosd.packSync" -}}
{{- $v := .root.Values.packSync -}}
{{- if not $v.repo }}{{ fail "packSync.repo is required when packSync.enabled" }}{{ end -}}
image: {{ $v.image | quote }}
args:
  - --repo={{ $v.repo }}
  - --ref={{ $v.ref }}
  - --root=/var/lib/contextos/pack-sync
  - --link=current
  - --period={{ $v.periodSeconds }}s
  {{- if .oneTime }}
  - --one-time
  {{- end }}
env:
  - { name: HOME, value: /tmp }
{{- with $v.secretName }}
envFrom:
  - secretRef: { name: {{ . | quote }} }
{{- end }}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
resources: {{- toYaml $v.resources | nindent 2 }}
volumeMounts:
  - { name: pack-sync, mountPath: /var/lib/contextos/pack-sync }
  - { name: pack-sync-tmp, mountPath: /tmp }
{{- end -}}
