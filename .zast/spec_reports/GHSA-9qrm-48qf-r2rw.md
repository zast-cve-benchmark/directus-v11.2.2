---
id: "GHSA-9qrm-48qf-r2rw"
category: "xss"
severity: "low"
refs:
  - url: "https://github.com/directus/directus/security/advisories/GHSA-9qrm-48qf-r2rw"
    type: ADVISORY
    conclusion: |-
      Directus allows an authenticated attacker to save cross-site scripting code to the database. The application injects an attacker-controlled parameter that is stored in the server and used by the client (layout_options field template) into an unsanitized DOM element in the v-field-template component, resulting in stored DOM-based XSS via layout_options. When chained with CVE-2024-6534 it can result in account takeover. Fixed in directus 11.3.3. (CWE-79)
  - url: "https://github.com/directus/directus"
    type: PACKAGE
---

# Cross-Site Scripting (XSS) — PATCH /presets/:pk

## Vulnerability Description

GHSA-9qrm-48qf-r2rw: Stored DOM-based XSS via the frontend v-field-template component. The modelValue bound to v-field-template comes from stored layout_options (field template), written via e.g. PATCH /presets/:pk. In setContent() at app/src/components/v-field-template/v-field-template.vue:256 the template string is concatenated into newInnerHTML and assigned directly to contentEl.value.innerHTML with no HTML sanitization, so a payload like {{title}}<img src=x onerror=...> is parsed and executed in any victim's session that opens the infected layout. Root cause: missing-control (missing HTML sanitize at the DOM sink).

## Impact Scope

- Endpoint: `PATCH /presets/:pk`

## Audit Path

1. `api/src/controllers/presets.ts:145` — The stored field template in layout_options is persisted via the presets update route without any HTML validation.

   ```javascript
   const primaryKey = await service.updateOne(req.params['pk']!, req.body);
   ```
2. `app/src/components/v-field-template/v-field-template.vue:232` — The stored template (props.modelValue) is split and rebuilt into an HTML string; non-field parts are wrapped in <span> with no escaping.

   ```javascript
   const newInnerHTML = props.modelValue.split(regex).map((part) => {
   ```
3. `app/src/components/v-field-template/v-field-template.vue:256` — The rebuilt markup is assigned to innerHTML with no dompurify sanitization, so injected <img onerror> etc. executes in the victim's session.

   ```javascript
   contentEl.value.innerHTML = newInnerHTML;
   ```

## Evidence Code

```javascript
// app/src/components/v-field-template/v-field-template.vue#L232
const newInnerHTML = props.modelValue.split(regex).map((part) => {
```

```javascript
// app/src/components/v-field-template/v-field-template.vue#L256
contentEl.value.innerHTML = newInnerHTML;
```

## Root Cause

`missing-control`
