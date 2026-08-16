package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/dewebprotocol/malt-core/mutation"
)

// MaxClientRootJSONBytes bounds every client-writer JSON document before
// decoding. The semantic collection ceilings in client_root.go apply after
// structural decoding and before core graph validation.
const MaxClientRootJSONBytes = 64 << 20

// DecodeUpdateView strictly decodes and validates one complete update view.
func DecodeUpdateView(data []byte) (UpdateView, error) {
	var value UpdateView
	if err := decodeClientRootJSON(data, &value); err != nil {
		return UpdateView{}, fmt.Errorf("decode update view: %w", err)
	}
	if err := value.Validate(); err != nil {
		return UpdateView{}, err
	}
	return value, nil
}

// DecodeSemanticIntent strictly decodes and validates one intent against the
// caller-selected complete update view.
func DecodeSemanticIntent(data []byte, view mutation.UpdateView) (SemanticIntent, error) {
	var value SemanticIntent
	if err := decodeClientRootJSON(data, &value); err != nil {
		return SemanticIntent{}, fmt.Errorf("decode semantic intent: %w", err)
	}
	if err := value.Validate(view); err != nil {
		return SemanticIntent{}, err
	}
	return value, nil
}

// DecodeClientRootBundle strictly decodes and validates one exact-root bundle.
func DecodeClientRootBundle(data []byte) (ClientRootBundle, error) {
	var value ClientRootBundle
	if err := decodeClientRootJSON(data, &value); err != nil {
		return ClientRootBundle{}, fmt.Errorf("decode client-root bundle: %w", err)
	}
	if err := value.Validate(); err != nil {
		return ClientRootBundle{}, err
	}
	return value, nil
}

// DecodeMaterializationReceipt strictly decodes a receipt and checks it against
// the exact submitted bundle.
func DecodeMaterializationReceipt(data []byte, bundle mutation.ClientRootBundle) (MaterializationReceipt, error) {
	var value MaterializationReceipt
	if err := decodeClientRootJSON(data, &value); err != nil {
		return MaterializationReceipt{}, fmt.Errorf("decode materialization receipt: %w", err)
	}
	if err := value.Validate(bundle); err != nil {
		return MaterializationReceipt{}, err
	}
	return value, nil
}

// DecodeWriterComputeResult strictly decodes and validates one browser writer
// result.
func DecodeWriterComputeResult(data []byte) (WriterComputeResult, error) {
	if len(data) == 0 {
		return WriterComputeResult{}, fmt.Errorf("decode writer compute result: client-root JSON is empty")
	}
	if len(data) > MaxClientRootJSONBytes {
		return WriterComputeResult{}, fmt.Errorf("decode writer compute result: client-root JSON exceeds %d bytes", MaxClientRootJSONBytes)
	}
	if !utf8.Valid(data) {
		return WriterComputeResult{}, fmt.Errorf("decode writer compute result: client-root JSON is not valid UTF-8")
	}
	var envelope struct {
		Profile string `json:"profile"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return WriterComputeResult{}, fmt.Errorf("decode writer compute result profile: %w", err)
	}
	if envelope.Profile == WriterComputeResultProfileV1 {
		var legacy writerComputeResultV1
		if err := decodeClientRootJSON(data, &legacy); err != nil {
			return WriterComputeResult{}, fmt.Errorf("decode writer compute result: %w", err)
		}
		value := WriterComputeResult{
			Profile:  legacy.Profile,
			Bundle:   legacy.Bundle,
			NextView: legacy.NextView,
			Metrics:  legacy.Metrics,
		}
		if err := value.Validate(); err != nil {
			return WriterComputeResult{}, err
		}
		return value, nil
	}
	var value WriterComputeResult
	if err := decodeClientRootJSON(data, &value); err != nil {
		return WriterComputeResult{}, fmt.Errorf("decode writer compute result: %w", err)
	}
	if err := value.Validate(); err != nil {
		return WriterComputeResult{}, err
	}
	return value, nil
}

func decodeClientRootJSON(data []byte, target any) error {
	if len(data) == 0 {
		return fmt.Errorf("client-root JSON is empty")
	}
	if len(data) > MaxClientRootJSONBytes {
		return fmt.Errorf("client-root JSON exceeds %d bytes", MaxClientRootJSONBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("client-root JSON is not valid UTF-8")
	}
	targetType := reflect.TypeOf(target)
	if targetType.Kind() != reflect.Pointer || targetType.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("client-root decode target must point to a struct")
	}
	if err := validateRequiredJSONShape(data, targetType.Elem()); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("unexpected trailing JSON: %w", err)
	}
	return nil
}

// validateRequiredJSONShape performs a streaming structural pass before typed
// decoding. In addition to unknown fields, it rejects duplicate fields, nulls,
// and missing required fields at every nested level. All client-root DTO fields
// are deliberately required; optional semantic values use explicit presence
// discriminators instead of optional JSON properties.
func validateRequiredJSONShape(data []byte, targetType reflect.Type) error {
	return validateRequiredJSONShapeWithPresence(data, targetType, nil)
}

func validateRequiredJSONShapeWithPresence(data []byte, targetType reflect.Type, presence map[string]struct{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := validateJSONToken(decoder, token, targetType, "$", true, presence); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("unexpected trailing JSON: %w", err)
	}
	return nil
}

func validateJSONToken(decoder *json.Decoder, token json.Token, targetType reflect.Type, path string, required bool, presence map[string]struct{}) error {
	for targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	if targetType == reflect.TypeFor[nullableJSONRawMessage]() {
		return skipJSONToken(decoder, token)
	}
	if token == nil {
		return fmt.Errorf("%s must not be null", path)
	}
	if targetType == reflect.TypeFor[json.RawMessage]() {
		return skipJSONToken(decoder, token)
	}
	switch targetType.Kind() {
	case reflect.Struct:
		delim, ok := token.(json.Delim)
		if !ok || delim != '{' {
			return fmt.Errorf("%s must be an object", path)
		}
		fields := jsonStructFields(targetType)
		seen := make(map[string]struct{}, len(fields))
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return fmt.Errorf("%s has a non-string field name", path)
			}
			field, exists := fields[name]
			if !exists {
				return fmt.Errorf("%s has unknown field %q", path, name)
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("%s has duplicate field %q", path, name)
			}
			seen[name] = struct{}{}
			if presence != nil {
				presence[path+"."+name] = struct{}{}
			}
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := validateJSONToken(decoder, valueToken, field.typ, path+"."+name, !field.optional, presence); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%s has an invalid object terminator", path)
		}
		for name, field := range fields {
			if _, exists := seen[name]; !exists && !field.optional {
				return fmt.Errorf("%s is missing required field %q", path, name)
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		delim, ok := token.(json.Delim)
		if !ok || delim != '[' {
			return fmt.Errorf("%s must be an array", path)
		}
		index := 0
		maxItems := maxClientRootSliceItems(targetType)
		for decoder.More() {
			if maxItems > 0 && index >= maxItems {
				return fmt.Errorf("%s exceeds %d items", path, maxItems)
			}
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := validateJSONToken(decoder, valueToken, targetType.Elem(), fmt.Sprintf("%s[%d]", path, index), true, presence); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%s has an invalid array terminator", path)
		}
		return nil
	case reflect.String:
		if _, ok := token.(string); !ok {
			return fmt.Errorf("%s must be a string", path)
		}
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("%s must be an unsigned integer", path)
		}
		return nil
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", path)
		}
		return nil
	default:
		return fmt.Errorf("%s has unsupported decoder type %s", path, targetType)
	}
}

func skipJSONToken(decoder *json.Decoder, token json.Token) error {
	delim, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := skipJSONToken(decoder, value); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := skipJSONToken(decoder, value); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delim)
	}
	return nil
}

func maxClientRootSliceItems(targetType reflect.Type) int {
	if targetType.Kind() == reflect.Array {
		return targetType.Len()
	}
	switch targetType.Elem() {
	case reflect.TypeFor[UpdateObject]():
		return MaxClientRootObjects
	case reflect.TypeFor[ArcEntry]():
		return MaxClientRootEntries
	case reflect.TypeFor[IntentTransition]():
		return MaxClientRootTransitions
	case reflect.TypeFor[IntentChange]():
		return MaxClientRootChanges
	case reflect.TypeFor[TransitionOutput]():
		return MaxClientRootTransitions
	case reflect.TypeFor[MapMaterializationWire]():
		return MaxClientRootTransitions
	case reflect.TypeFor[MaterializationEntryWire]():
		return MaxClientRootMaterializationEntries
	case reflect.TypeFor[string]():
		return MaxClientRootPayloadCIDs
	default:
		return 0
	}
}

type jsonStructField struct {
	typ      reflect.Type
	optional bool
}

func jsonStructFields(targetType reflect.Type) map[string]jsonStructField {
	fields := make(map[string]jsonStructField, targetType.NumField())
	for index := 0; index < targetType.NumField(); index++ {
		field := targetType.Field(index)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("json")
		name, options, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = jsonStructField{typ: field.Type, optional: strings.Contains(options, "omitempty")}
	}
	return fields
}
