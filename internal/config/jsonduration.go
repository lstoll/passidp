package config

import (
	"encoding/json"
	"time"
)

// JSONDuration is a wrapper around time.Duration that implements the
// json.Unmarshaler and json.Marshaler interfaces using the standard go duration
// parsing.
type JSONDuration time.Duration

func (d *JSONDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = JSONDuration(dur)
	return nil
}

func (d JSONDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d JSONDuration) Duration() time.Duration {
	return time.Duration(d)
}
