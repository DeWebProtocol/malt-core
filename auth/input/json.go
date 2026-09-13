package input

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

// JSON uses decimal strings for uint64 indices/selectors so browser callers
// never round an authentication coordinate through a JavaScript number.
func (v Value) MarshalJSON() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	if v.Kind == Index || v.Kind == System {
		return json.Marshal(struct {
			Kind   Kind   `json:"kind"`
			Number string `json:"number"`
		}{v.Kind, strconv.FormatUint(v.Number, 10)})
	}
	data := v.Data
	if data == nil {
		data = []byte{}
	}
	return json.Marshal(struct {
		Kind Kind   `json:"kind"`
		Data []byte `json:"data"`
	}{v.Kind, data})
}
func (v *Value) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("input must be an object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("input field must be a string")
		}
		if _, seen := fields[name]; seen {
			return errors.New("duplicate input field")
		}
		if name != "kind" && name != "data" && name != "number" {
			return errors.New("unknown input field")
		}
		var raw json.RawMessage
		if err = decoder.Decode(&raw); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("null input field")
		}
		fields[name] = raw
	}
	if _, err = decoder.Token(); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing input JSON")
	}
	if len(fields) != 2 {
		return errors.New("input requires kind and exactly one value")
	}
	var next Value
	if err = json.Unmarshal(fields["kind"], &next.Kind); err != nil {
		return err
	}
	if next.Kind == Index || next.Kind == System {
		var number string
		if err = json.Unmarshal(fields["number"], &number); err != nil {
			return err
		}
		parsed, err := strconv.ParseUint(number, 10, 64)
		if err != nil {
			return err
		}
		if strconv.FormatUint(parsed, 10) != number {
			return errors.New("noncanonical uint64 input")
		}
		next.Number = parsed
	} else {
		var text string
		if err = json.Unmarshal(fields["data"], &text); err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil {
			return err
		}
		if base64.StdEncoding.EncodeToString(decoded) != text {
			return errors.New("noncanonical base64 input")
		}
		next.Data = decoded
	}
	if err = next.Validate(); err != nil {
		return err
	}
	*v = next
	return nil
}
