package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

var ErrNonCanonical = errors.New("JSON is not canonical")

// Canonicalize accepts the JSON value subset used by forge actions: objects,
// arrays, strings, booleans, null and integers. Object keys are sorted and all
// insignificant whitespace is removed.
func Canonicalize(input []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, fmt.Errorf("decode trailing JSON: %w", err)
	}

	var output bytes.Buffer
	if err := writeCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func Verify(input []byte) error {
	canonical, err := Canonicalize(input)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, input) {
		return ErrNonCanonical
	}
	return nil
}

func Unmarshal(input []byte, destination any) error {
	if err := Verify(input); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func writeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		output.Write(encoded)
	case json.Number:
		number := typed.String()
		if !validInteger(number) {
			return fmt.Errorf("non-integer number %q is not supported", number)
		}
		output.WriteString(number)
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return err
			}
			output.Write(encoded)
			output.WriteByte(':')
			if err := writeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}

func validInteger(value string) bool {
	if value == "" || value == "-" {
		return false
	}
	unsigned := strings.TrimPrefix(value, "-")
	if unsigned == "" {
		return false
	}
	if len(unsigned) > 1 && unsigned[0] == '0' {
		return false
	}
	for _, character := range unsigned {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != "-0"
}
