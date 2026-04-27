package config

import (
	"reflect"

	"github.com/BurntSushi/toml"
)

// computeDefinedTOMLKeys returns a map of TOML keys (struct tags) that were explicitly
// provided in the TOML file, based on BurntSushi's MetaData.
func computeDefinedTOMLKeys(meta toml.MetaData, cfg ClientConfig) map[string]bool {
	out := map[string]bool{}

	rt := reflect.TypeOf(cfg)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		if meta.IsDefined(tag) {
			out[tag] = true
		}
	}
	return out
}

// mapDefinedFieldNamesToTOMLKeys maps JSON-defined field names (struct field names)
// to their TOML tags, so the rest of the system can talk in "client_config.toml keys".
func mapDefinedFieldNamesToTOMLKeys(defined map[string]bool, cfg ClientConfig) map[string]bool {
	out := map[string]bool{}
	if len(defined) == 0 {
		return out
	}

	rt := reflect.TypeOf(cfg)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !defined[f.Name] {
			continue
		}
		tag := f.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		out[tag] = true
	}
	return out
}

