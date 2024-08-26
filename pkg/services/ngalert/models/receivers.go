package models

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"math"
	"sort"
	"strings"
	"unsafe"

	alertingNotify "github.com/grafana/alerting/notify"

	"github.com/grafana/grafana/pkg/services/ngalert/notifier/channels_config"
)

// GetReceiverQuery represents a query for a single receiver.
type GetReceiverQuery struct {
	OrgID   int64
	Name    string
	Decrypt bool
}

// GetReceiversQuery represents a query for receiver groups.
type GetReceiversQuery struct {
	OrgID   int64
	Names   []string
	Limit   int
	Offset  int
	Decrypt bool
}

// ListReceiversQuery represents a query for listing receiver groups.
type ListReceiversQuery struct {
	OrgID  int64
	Names  []string
	Limit  int
	Offset int
}

// Receiver is the domain model representation of a receiver / contact point.
type Receiver struct {
	UID          string
	Name         string
	Integrations []*Integration
	Provenance   Provenance
	Version      string
}

func (r *Receiver) Clone() Receiver {
	clone := Receiver{
		UID:        r.UID,
		Name:       r.Name,
		Provenance: r.Provenance,
		Version:    r.Version,
	}

	if r.Integrations != nil {
		clone.Integrations = make([]*Integration, len(r.Integrations))
		for i, integration := range r.Integrations {
			cloneIntegration := integration.Clone()
			clone.Integrations[i] = &cloneIntegration
		}
	}
	return clone
}

// Encrypt encrypts all integrations.
func (r *Receiver) Encrypt(encryptFn EncryptFn) error {
	for _, integration := range r.Integrations {
		if err := integration.Encrypt(encryptFn); err != nil {
			return err
		}
	}
	return nil
}

// Decrypt decrypts all integrations.
func (r *Receiver) Decrypt(decryptFn DecryptFn) error {
	var errs []error
	for _, integration := range r.Integrations {
		if err := integration.Decrypt(decryptFn); err != nil {
			errs = append(errs, fmt.Errorf("failed to decrypt integration %s: %w", integration.UID, err))
		}
	}
	return errors.Join(errs...)
}

// Redact redacts all integrations.
func (r *Receiver) Redact(redactFn RedactFn) {
	for _, integration := range r.Integrations {
		integration.Redact(redactFn)
	}
}

// WithExistingSecureFields copies secure settings from an existing receivers for each integration. Which fields to copy
// is determined by the integrationSecureFields map, which contains a list of secure fields for each integration UID.
func (r *Receiver) WithExistingSecureFields(existing *Receiver, integrationSecureFields map[string][]string) {
	existingIntegrations := make(map[string]*Integration, len(existing.Integrations))
	for _, integration := range existing.Integrations {
		existingIntegrations[integration.UID] = integration
	}

	for _, integration := range r.Integrations {
		if integration.UID == "" {
			// This is a new integration, so we don't need to copy any secure fields.
			continue
		}
		fields := integrationSecureFields[integration.UID]
		if len(fields) > 0 {
			integration.WithExistingSecureFields(existingIntegrations[integration.UID], fields)
		}
	}
}

// Validate validates all integration settings, ensuring that the integrations are correctly configured.
func (r *Receiver) Validate(decryptFn DecryptFn) error {
	var errs []error
	for _, integration := range r.Integrations {
		if err := integration.Validate(decryptFn); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Integration is the domain model representation of an integration.
type Integration struct {
	UID                   string
	Name                  string
	Config                IntegrationConfig
	DisableResolveMessage bool
	// Settings can contain both secure and non-secure settings either unencrypted or redacted.
	Settings map[string]any
	// SecureSettings can contain only secure settings either encrypted or redacted.
	SecureSettings map[string]string
}

// IntegrationConfig represents the configuration of an integration. It contains the type and information about the fields.
type IntegrationConfig struct {
	Type   string
	Fields map[string]IntegrationField
}

// IntegrationField represents a field in an integration configuration.
type IntegrationField struct {
	Name   string
	Fields map[string]IntegrationField
	Secure bool
}

type IntegrationFieldPath []string

func (f IntegrationFieldPath) Head() string {
	if len(f) > 0 {
		return f[0]
	}
	return ""
}

func (f IntegrationFieldPath) Tail() []string {
	return f[1:]
}

func (f IntegrationFieldPath) IsLeaf() bool {
	return len(f) == 1
}

func (f IntegrationFieldPath) String() string {
	return strings.Join(f, ".")
}

// IntegrationConfigFromType returns an integration configuration for a given integration type. If the integration type is
// not found an error is returned.
func IntegrationConfigFromType(integrationType string) (IntegrationConfig, error) {
	config, err := channels_config.ConfigForIntegrationType(integrationType)
	if err != nil {
		return IntegrationConfig{}, err
	}

	integrationConfig := IntegrationConfig{Type: config.Type, Fields: make(map[string]IntegrationField, len(config.Options))}

	for _, option := range config.Options {
		integrationConfig.Fields[option.PropertyName] = notifierOptionToIntegrationField(option)
	}
	return integrationConfig, nil
}

func notifierOptionToIntegrationField(option channels_config.NotifierOption) IntegrationField {
	f := IntegrationField{
		Name:   option.PropertyName,
		Secure: option.Secure,
		Fields: make(map[string]IntegrationField, len(option.SubformOptions)),
	}
	for _, subformOption := range option.SubformOptions {
		f.Fields[subformOption.PropertyName] = notifierOptionToIntegrationField(subformOption)
	}
	return f
}

// IsSecureField returns true if the field is both known and marked as secure in the integration configuration.
func (config *IntegrationConfig) IsSecureField(path IntegrationFieldPath) bool {
	f := config.GetField(path)
	if f == nil {
		return false
	}
	return f.Secure
}

func (config *IntegrationConfig) GetField(path IntegrationFieldPath) *IntegrationField {
	for _, integrationField := range config.Fields {
		if strings.EqualFold(integrationField.Name, path[0]) {
			return integrationField.GetField(path[1:]...)
		}
	}
	return nil
}

func (config *IntegrationConfig) GetSecretFields() []IntegrationFieldPath {
	return traverseFields(config.Fields, nil, func(i IntegrationField) bool {
		return i.Secure
	})
}

func traverseFields(flds map[string]IntegrationField, parentPath []string, predicate func(i IntegrationField) bool) []IntegrationFieldPath {
	var result []IntegrationFieldPath
	for key, field := range flds {
		if predicate(field) {
			result = append(result, append(parentPath, key))
		}
		if len(field.Fields) > 0 {
			result = append(result, traverseFields(field.Fields, append(parentPath, key), predicate)...)
		}
	}
	return result
}

func (config *IntegrationConfig) Clone() IntegrationConfig {
	clone := IntegrationConfig{
		Type: config.Type,
	}

	if len(config.Fields) > 0 {
		clone.Fields = make(map[string]IntegrationField, len(config.Fields))
		for key, field := range config.Fields {
			clone.Fields[key] = field.Clone()
		}
	}
	return clone
}

func (field *IntegrationField) GetField(path ...string) *IntegrationField {
	for _, integrationField := range field.Fields {
		if strings.EqualFold(integrationField.Name, path[0]) {
			return integrationField.GetField(path[1:]...)
		}
	}
	return nil
}

func (field *IntegrationField) Clone() IntegrationField {
	return IntegrationField{
		Name:   field.Name,
		Secure: field.Secure,
	}
}

func (integration *Integration) Clone() Integration {
	return Integration{
		UID:                   integration.UID,
		Name:                  integration.Name,
		Config:                integration.Config.Clone(),
		DisableResolveMessage: integration.DisableResolveMessage,
		Settings:              maps.Clone(integration.Settings),
		SecureSettings:        maps.Clone(integration.SecureSettings),
	}
}

// Encrypt encrypts all fields in Settings that are marked as secure in the integration configuration. The encrypted values
// are stored in SecureSettings and the original values are removed from Settings.
// If a field is already in SecureSettings it is not encrypted again.
func (integration *Integration) Encrypt(encryptFn EncryptFn) error {
	secretFieldPaths := integration.Config.GetSecretFields()
	if len(secretFieldPaths) == 0 {
		return nil
	}
	var errs []error
	for _, path := range secretFieldPaths {
		unencryptedSecureValue, ok, err := extractField(integration.Settings, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to extract secret field by path '%s': %w", path, err))
		}
		if !ok {
			continue
		}
		if _, exists := integration.SecureSettings[path.String()]; exists {
			continue
		}
		encrypted, err := encryptFn(unencryptedSecureValue)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to encrypt secure setting '%s': %w", path.String(), err))
		}
		integration.SecureSettings[path.String()] = encrypted
	}
	return errors.Join(errs...)
}

func extractField(settings map[string]any, path IntegrationFieldPath) (string, bool, error) {
	val, ok := settings[path.Head()]
	if !ok {
		return "", false, nil
	}
	if path.IsLeaf() {
		secret, ok := val.(string)
		if !ok {
			return "", false, fmt.Errorf("expected string but got %T", val)
		}
		return secret, true, nil
	}
	sub, ok := val.(map[string]any)
	if !ok {
		return "", false, fmt.Errorf("expected nested object but got %T", val)
	}
	return extractField(sub, path.Tail())
}

func getFieldValue(settings map[string]any, path IntegrationFieldPath) (any, bool) {
	val, ok := settings[path.Head()]
	if !ok {
		return nil, false
	}
	if path.IsLeaf() {
		return val, true
	}
	sub, ok := val.(map[string]any)
	if !ok {
		return nil, false
	}
	return getFieldValue(sub, path.Tail())
}

func setField(settings map[string]any, path IntegrationFieldPath, valueFn func(current any) any, skipIfNotExist bool) error {
	if path.IsLeaf() {
		current, ok := settings[path.Head()]
		if skipIfNotExist && !ok {
			return nil
		}
		settings[path.Head()] = valueFn(current)
		return nil
	}
	val, ok := settings[path.Head()]
	if !ok {
		if skipIfNotExist {
			return nil
		}
		val = map[string]any{}
		settings[path.Head()] = val
	}
	sub, ok := val.(map[string]any)
	if !ok {
		return fmt.Errorf("expected nested object but got %T", val)
	}
	return setField(sub, path.Tail(), valueFn, skipIfNotExist)
}

// Decrypt decrypts all fields in SecureSettings and moves them to Settings.
// The original values are removed from SecureSettings.
func (integration *Integration) Decrypt(decryptFn DecryptFn) error {
	var errs []error
	for key, secureVal := range integration.SecureSettings {
		decrypted, err := decryptFn(secureVal)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to decrypt secure setting '%s': %w", key, err))
		}
		delete(integration.SecureSettings, key)

		path := IntegrationFieldPath(strings.Split(key, "."))
		err = setField(integration.Settings, path, func(current any) any {
			return decrypted
		}, false)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set field '%s': %w", key, err))
		}
	}
	return errors.Join(errs...)
}

// Redact redacts all fields in SecureSettings and moves them to Settings.
// The original values are removed from SecureSettings.
func (integration *Integration) Redact(redactFn RedactFn) {
	for _, path := range integration.Config.GetSecretFields() {
		_ = setField(integration.Settings, path, func(current any) any {
			s, _ := current.(string)
			return redactFn(s)
		}, true)
	}

	for key, secureVal := range integration.SecureSettings { // TODO: Should we trust that the receiver is stored correctly or use known secure settings?
		_ = setField(integration.Settings, strings.Split(key, "."), func(any) any {
			return redactFn(secureVal)
		}, false)
		delete(integration.SecureSettings, key)
	}
}

// WithExistingSecureFields copies secure settings from an existing integration. Which fields to copy is determined by the
// fields slice.
// Any fields found in Settings or SecureSettings are removed, even if they don't appear in the existing integration.
func (integration *Integration) WithExistingSecureFields(existing *Integration, fields []string) {
	// Now for each field marked as secure, we copy the value from the existing receiver.
	for _, secureField := range fields {
		delete(integration.Settings, secureField) // Ensure secure fields are removed from new settings and secure settings.
		delete(integration.SecureSettings, secureField)
		if existing != nil {
			if existingVal, ok := existing.SecureSettings[secureField]; ok {
				integration.SecureSettings[secureField] = existingVal
			}
		}
	}
}

// SecureFields returns a map of all secure fields in the integration. This includes fields in SecureSettings and fields
// in Settings that are marked as secure in the integration configuration.
func (integration *Integration) SecureFields() map[string]bool {
	secureFields := make(map[string]bool, len(integration.SecureSettings))
	if len(integration.SecureSettings) > 0 {
		for key := range integration.SecureSettings {
			secureFields[key] = true
		}
	}
	// We mark secure fields in the settings as well. This is to ensure legacy behaviour for redacted secure settings.
	for _, path := range integration.Config.GetSecretFields() {
		if secureFields[path.String()] {
			continue
		}
		value, ok := getFieldValue(integration.Settings, path)
		if !ok || value == nil {
			continue
		}
		if v, _ := value.(string); v != "" {
			secureFields[path.String()] = true
		}
	}

	return secureFields
}

// Validate validates the integration settings, ensuring that the integration is correctly configured.
func (integration *Integration) Validate(decryptFn DecryptFn) error {
	decrypted := integration.Clone()
	if err := decrypted.Decrypt(decryptFn); err != nil {
		return err
	}
	jsonBytes, err := json.Marshal(decrypted.Settings)
	if err != nil {
		return err
	}

	return ValidateIntegration(context.Background(), alertingNotify.GrafanaIntegrationConfig{
		UID:                   decrypted.UID,
		Name:                  decrypted.Name,
		Type:                  decrypted.Config.Type,
		DisableResolveMessage: decrypted.DisableResolveMessage,
		Settings:              jsonBytes,
		SecureSettings:        decrypted.SecureSettings,
	}, alertingNotify.NoopDecrypt)
}

func ValidateIntegration(ctx context.Context, integration alertingNotify.GrafanaIntegrationConfig, decryptFunc alertingNotify.GetDecryptedValueFn) error {
	if integration.Type == "" {
		return fmt.Errorf("type should not be an empty string")
	}
	if integration.Settings == nil {
		return fmt.Errorf("settings should not be empty")
	}

	_, err := alertingNotify.BuildReceiverConfiguration(ctx, &alertingNotify.APIReceiver{
		GrafanaIntegrations: alertingNotify.GrafanaIntegrations{
			Integrations: []*alertingNotify.GrafanaIntegrationConfig{&integration},
		},
	}, decryptFunc)
	if err != nil {
		return err
	}
	return nil
}

type EncryptFn = func(string) (string, error)
type DecryptFn = func(string) (string, error)
type RedactFn = func(string) string

// Identified describes a class of resources that have a UID. Created to abstract required fields for authorization.
type Identified interface {
	GetUID() string
}

func (r *Receiver) GetUID() string {
	return r.UID
}

func (r *Receiver) Fingerprint() string {
	sum := fnv.New64()

	writeBytes := func(b []byte) {
		_, _ = sum.Write(b)
		// add a byte sequence that cannot happen in UTF-8 strings.
		_, _ = sum.Write([]byte{255})
	}
	writeString := func(s string) {
		if len(s) == 0 {
			writeBytes(nil)
			return
		}
		// #nosec G103
		// avoid allocation when converting string to byte slice
		writeBytes(unsafe.Slice(unsafe.StringData(s), len(s)))
	}
	// this temp slice is used to convert ints to bytes.
	tmp := make([]byte, 8)
	writeInt := func(u int) {
		binary.LittleEndian.PutUint64(tmp, uint64(u))
		writeBytes(tmp)
	}

	writeIntegration := func(in *Integration) {
		writeString(in.UID)
		writeString(in.Name)

		// Do not include fields in fingerprint as these are not part of the receiver definition.
		writeString(in.Config.Type)

		if in.DisableResolveMessage {
			writeInt(1)
		} else {
			writeInt(0)
		}

		// allocate a slice that will be used for sorting keys, so we allocate it only once
		var keys []string
		maxLen := int(math.Max(float64(len(in.Settings)), float64(len(in.SecureSettings))))
		if maxLen > 0 {
			keys = make([]string, maxLen)
		}

		writeSecureSettings := func(secureSettings map[string]string) {
			// maps do not guarantee predictable sequence of keys.
			// Therefore, to make hash stable, we need to sort keys
			if len(secureSettings) == 0 {
				return
			}
			idx := 0
			for k := range secureSettings {
				keys[idx] = k
				idx++
			}
			sub := keys[:idx]
			sort.Strings(sub)
			for _, name := range sub {
				writeString(name)
				writeString(secureSettings[name])
			}
		}
		writeSecureSettings(in.SecureSettings)

		writeSettings := func(settings map[string]any) {
			// maps do not guarantee predictable sequence of keys.
			// Therefore, to make hash stable, we need to sort keys
			if len(settings) == 0 {
				return
			}
			idx := 0
			for k := range settings {
				keys[idx] = k
				idx++
			}
			sub := keys[:idx]
			sort.Strings(sub)
			for _, name := range sub {
				writeString(name)

				// TODO: Improve this.
				v := settings[name]
				bytes, err := json.Marshal(v)
				if err != nil {
					writeString(fmt.Sprintf("%+v", v))
				} else {
					writeBytes(bytes)
				}
			}
		}
		writeSettings(in.Settings)
	}

	// fields that determine the rule state
	writeString(r.UID)
	writeString(r.Name)
	writeString(string(r.Provenance))

	for _, integration := range r.Integrations {
		writeIntegration(integration)
	}

	return fmt.Sprintf("%016x", sum.Sum64())
}
