// Command openapi generates the administration contract from shared Go models.
package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"waf/internal/config"
	"waf/internal/policy"
	"waf/internal/store"
	"waf/internal/tlsmgr"
)

type object = map[string]any

var schemas = object{}

func ref(name string) object { return object{"$ref": "#/components/schemas/" + name} }
func schema(t reflect.Type) any {
	if t.Kind() == reflect.Pointer {
		return schema(t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		if _, ok := schemas[t.Name()]; ok {
			return ref(t.Name())
		}
		props := object{}
		schemas[t.Name()] = object{"type": "object", "additionalProperties": false, "properties": props}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			props[tag] = schema(f.Type)
		}
		return ref(t.Name())
	case reflect.Slice, reflect.Array:
		return object{"type": []string{"array", "null"}, "items": schema(t.Elem())}
	case reflect.Map:
		return object{"type": "object", "additionalProperties": schema(t.Elem())}
	case reflect.Bool:
		return object{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Uint64:
		return object{"type": "integer", "format": "int64"}
	case reflect.Float64:
		return object{"type": "number"}
	default:
		return object{"type": "string"}
	}
}
func props(name string) object { return schemas[name].(object)["properties"].(object) }
func named(name string, p object, required ...string) object {
	schemas[name] = object{"type": "object", "additionalProperties": false, "properties": p, "required": required}
	return ref(name)
}
func array(v any) object { return object{"type": "array", "items": v} }
func stringType() object { return object{"type": "string"} }
func numberType() object { return object{"type": "integer", "format": "int64"} }
func main() {
	for _, v := range []any{config.Bundle{}, config.Site{}, config.Upstream{}, config.ManagedPolicy{}, config.Exclusion{}, config.CustomRule{}, config.RateLimitPolicy{}, config.RoutePolicy{}, config.BotPolicy{}, store.Draft{}, store.Revision{}, store.User{}, store.Event{}, store.Audit{}, tlsmgr.Status{}, tlsmgr.Credential{}, policy.ManagedRule{}} {
		schema(reflect.TypeOf(v))
	}
	for name, fields := range map[string][]string{"Bundle": {"sites"}, "Site": {"id", "domains", "upstreams"}, "Upstream": {"url"}, "CustomRule": {"id", "expression", "action"}, "RateLimitPolicy": {"id", "key", "requests_per_second", "burst"}, "RoutePolicy": {"path_prefix"}, "Draft": {"base_revision", "version", "bundle"}} {
		schemas[name].(object)["required"] = fields
	}
	props("Site")["id"] = object{"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}
	props("ManagedPolicy")["mode"] = object{"type": "string", "enum": []string{"off", "observe", "block"}, "default": "observe"}
	props("CustomRule")["action"] = object{"type": "string", "enum": []string{"block", "log", "challenge", "skip"}}
	props("CustomRule")["expression"] = object{"type": "string", "maxLength": 4096}
	props("RoutePolicy")["body_mode"] = object{"type": "string", "enum": []string{"inspect", "stream"}, "default": "inspect"}
	props("RoutePolicy")["max_body_bytes"] = object{"type": "integer", "minimum": 1, "description": "inspect defaults to 8388608 bytes; stream requires an explicit value; bounded by configured node budget."}
	props("RoutePolicy")["max_duration_seconds"] = object{"type": "integer", "minimum": 0, "maximum": 86400, "description": "A positive value is mandatory for stream routes."}
	props("Exclusion")["target"] = object{"type": "string", "description": "Optional ARGS:name, ARGS_NAMES:name, REQUEST_HEADERS:name or REQUEST_COOKIES:name. Control rules cannot be excluded."}
	props("Credential")["api_token"] = object{"type": "string", "minLength": 1, "maxLength": 4096, "writeOnly": true}
	props("Credential")["zone_token"] = object{"type": "string", "maxLength": 4096, "writeOnly": true}
	props("User")["role"] = object{"type": "string", "enum": []string{"admin", "operator", "viewer"}}
	password := object{"type": "string", "minLength": 12, "maxLength": 256, "writeOnly": true}
	session := named("SessionResponse", object{"user": ref("User"), "csrf_token": stringType(), "development": object{"type": "boolean"}, "expires": object{"type": "string", "format": "date-time"}}, "user", "csrf_token", "development")
	login := named("LoginRequest", object{"username": stringType(), "password": password, "code": object{"type": "string", "description": "Fresh TOTP or unused recovery code. Development mode permits an empty value."}}, "username", "password", "code")
	expected := named("PublishRequest", object{"version": numberType(), "base_revision": numberType()}, "version", "base_revision")
	rollback := named("RollbackRequest", object{"revision": numberType(), "version": numberType(), "base_revision": numberType()}, "revision", "version", "base_revision")
	published := named("PublishResponse", object{"revision": numberType(), "warning": stringType()}, "revision")
	ok := named("Success", object{"ok": object{"type": "boolean"}, "warning": stringType()}, "ok")
	errSchema := named("Error", object{"error": stringType()}, "error")
	createUser := named("CreateUser", object{"username": stringType(), "password": password, "role": props("User")["role"]}, "username", "password", "role")
	enrollment := named("Enrollment", object{"user": ref("User"), "totp_secret": stringType(), "otpauth_url": stringType(), "recovery_codes": array(stringType())}, "user", "totp_secret", "otpauth_url", "recovery_codes")
	evaluate := named("EvaluateRequest", object{"expression": object{"type": "string", "maxLength": 4096}, "sample": object{"type": "object", "additionalProperties": true}}, "expression")
	evaluation := named("EvaluateResponse", object{"valid": object{"type": "boolean"}, "matches": object{"type": "boolean"}}, "valid", "matches")
	overview := named("Overview", object{"stats": object{"type": "object", "additionalProperties": numberType()}, "revision": numberType(), "crs_version": stringType(), "development": object{"type": "boolean"}, "upstreams": array(object{"type": "object", "properties": object{"site_id": stringType(), "url": stringType(), "healthy": object{"type": "boolean"}, "health_path": stringType()}}), "certificates": array(ref("Status"))}, "stats", "revision", "crs_version", "upstreams", "certificates")
	backupRequest := named("BackupRequest", object{"password": password}, "password")
	backupInfo := named("BackupInfo", object{"name": stringType(), "size": numberType(), "created": object{"type": "string", "format": "date-time"}}, "name")
	paths := object{}
	add := func(path, method, summary, role string, body, response any, status string) {
		operation := object{"summary": summary, "operationId": strings.NewReplacer("/", "_", "{", "", "}", "").Replace(method + path), "tags": []string{strings.Split(strings.TrimPrefix(path, "/"), "/")[0]}, "x-required-role": role}
		security := object{"session": []string{}}
		parameters := []any{}
		if method != "get" {
			security["csrf"] = []string{}
			parameters = append(parameters, object{"in": "header", "name": "Origin", "required": true, "schema": stringType(), "description": "Must match the exact console origin."})
		}
		if role != "anonymous" {
			operation["security"] = []any{security}
		} else {
			operation["security"] = []any{}
		}
		for _, name := range []string{"id", "name"} {
			if strings.Contains(path, "{"+name+"}") {
				parameters = append(parameters, object{"in": "path", "name": name, "required": true, "schema": stringType()})
			}
		}
		if path == "/events" || path == "/audit" {
			parameters = append(parameters, object{"in": "query", "name": "before", "schema": numberType(), "description": "Exclusive event/audit ID cursor; omit for newest records."})
		}
		if path == "/events" {
			for _, name := range []string{"site_id", "action"} {
				parameters = append(parameters, object{"in": "query", "name": name, "schema": stringType()})
			}
			parameters = append(parameters, object{"in": "query", "name": "limit", "schema": object{"type": "integer", "minimum": 1, "maximum": 200, "default": 100}})
		}
		operation["parameters"] = parameters
		if body != nil {
			operation["requestBody"] = object{"required": true, "content": object{"application/json": object{"schema": body}}}
		}
		responses := object{status: object{"description": "Success", "content": object{"application/json": object{"schema": response}}}}
		for _, code := range []string{"400", "401", "403", "404", "409", "413", "415", "429", "500", "503"} {
			responses[code] = object{"description": "Request rejected or operation failed; see error.", "content": object{"application/json": object{"schema": errSchema}}}
		}
		if path == "/backups/{name}" {
			responses[status] = object{"description": "age-encrypted backup file", "content": object{"application/octet-stream": object{"schema": object{"type": "string", "format": "binary"}}}}
		}
		operation["responses"] = responses
		if paths[path] == nil {
			paths[path] = object{}
		}
		paths[path].(object)[method] = operation
	}
	add("/auth/login", "post", "Authenticate using password and TOTP; sets an HttpOnly session cookie.", "anonymous", login, session, "200")
	add("/auth/session", "get", "Get current identity and CSRF token.", "viewer", nil, session, "200")
	add("/auth/logout", "post", "Revoke current session.", "viewer", object{"type": "object"}, ok, "200")
	add("/overview", "get", "Get retained event aggregates and node state.", "viewer", nil, overview, "200")
	add("/config/active", "get", "Read active configuration revision.", "viewer", nil, ref("Revision"), "200")
	add("/config/draft", "get", "Read draft with optimistic concurrency tokens.", "viewer", nil, ref("Draft"), "200")
	add("/config/draft", "put", "Save the complete draft; stale version returns 409.", "operator", ref("Draft"), ref("Draft"), "200")
	add("/config/validate", "post", "Compile all policies without publishing or issuing certificates.", "operator", ref("Bundle"), object{"type": "object", "properties": object{"valid": object{"type": "boolean"}, "crs_version": stringType(), "bundle": ref("Bundle")}}, "200")
	add("/config/publish", "post", "Compile and atomically publish the stored draft.", "operator", expected, published, "200")
	add("/config/rollback", "post", "Replace draft with an earlier configuration and publish a new revision.", "operator", rollback, published, "200")
	add("/config/revisions", "get", "List up to 100 retained revisions.", "viewer", nil, array(ref("Revision")), "200")
	add("/rules/catalog", "get", "List bundled CRS detector and control rules.", "viewer", nil, object{"type": "object", "properties": object{"version": stringType(), "rules": array(ref("ManagedRule"))}}, "200")
	add("/rules/evaluate", "post", "Compile CEL and optionally evaluate a sample request context.", "operator", evaluate, evaluation, "200")
	add("/certificates", "get", "Read automatic certificate state; contains no private keys.", "viewer", nil, array(ref("Status")), "200")
	add("/credentials", "get", "List credential names and update times; never return tokens.", "admin", nil, array(object{"type": "object", "properties": object{"name": stringType(), "updated": stringType()}}), "200")
	add("/credentials/{name}", "put", "Encrypt and replace a Cloudflare credential, then refresh automation.", "admin", ref("Credential"), ok, "200")
	add("/users", "get", "List local users.", "admin", nil, array(ref("User")), "200")
	add("/users", "post", "Create user and return one-time MFA enrollment material.", "admin", createUser, enrollment, "201")
	add("/users/{id}", "patch", "Update role or disabled status and revoke sessions; preserve the last admin.", "admin", object{"type": "object", "additionalProperties": false, "required": []string{"role", "disabled"}, "properties": object{"role": props("User")["role"], "disabled": object{"type": "boolean"}}}, ok, "200")
	add("/events", "get", "Read sanitized access and security events.", "viewer", nil, array(ref("Event")), "200")
	add("/audit", "get", "Read administration audit trail.", "viewer", nil, array(ref("Audit")), "200")
	add("/backups", "get", "List encrypted local backups.", "admin", nil, array(backupInfo), "200")
	add("/backups", "post", "Create a consistent database snapshot and encrypted certificate backup.", "admin", backupRequest, backupInfo, "201")
	add("/backups/{name}", "get", "Download an encrypted backup; original master.key remains separate.", "admin", nil, nil, "200")
	add("/openapi.json", "get", "Download this contract.", "viewer", nil, object{"type": "object"}, "200")
	spec := object{"openapi": "3.1.0", "info": object{"title": "WAF Administration API", "version": "0.1.0", "description": "All paths are relative to /api/v1 on the dedicated administration domain. Mutations require the session cookie, X-CSRF-Token and exact Origin. Body limit: 2 MiB. Site/rule resources are edited together through the versioned configuration draft. Development mode uses the waf_session_dev cookie on loopback HTTP."}, "servers": []any{object{"url": "/api/v1"}}, "paths": paths, "components": object{"schemas": schemas, "securitySchemes": object{"session": object{"type": "apiKey", "in": "cookie", "name": "__Host-waf_session"}, "csrf": object{"type": "apiKey", "in": "header", "name": "X-CSRF-Token"}}}}
	raw, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile("internal/admin/openapi.json", append(raw, '\n'), 0644); err != nil {
		panic(err)
	}
}
