{{- define "addy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "addy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "addy.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "addy.labels" -}}
app.kubernetes.io/name: {{ include "addy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/*
Refusals, evaluated at template time so a bad release fails BEFORE anything is
applied rather than as a CrashLoopBackOff somebody has to read logs to explain.
*/}}
{{- define "addy.validate" -}}
{{- if not .Values.domain -}}
{{- fail "addy needs a domain: set `domain`. It refuses to serve a name it was not configured for, which is what stops it answering for somebody else's." -}}
{{- end -}}
{{- if and .Values.turn.enabled (not .Values.turn.publicIP) -}}
{{- fail "turn.enabled needs turn.publicIP. TURN puts that address in the protocol and cannot infer it behind a Service; a relay that guesses allocates addresses nobody can reach, and fails only under the NAT conditions it exists for." -}}
{{- end -}}
{{- end -}}
