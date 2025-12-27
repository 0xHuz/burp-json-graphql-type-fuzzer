# Burp JSON & GraphQL Type Fuzzer

A Burp Suite extension that performs **JSON type confusion testing** and **GraphQL variable fuzzing** using **type-aware payloads**.

This extension supports two fuzzing modes:

- **JSON Type Confusion** – aggressive type swapping for classic deserialization and logic flaws
- **GraphQL Variable Fuzzing** – schema-friendly variable mutation without type confusion

---

## Features

### JSON Type Confusion Mode

- Mutates JSON request bodies
- Replaces values with valid JSON data types
- Traverses deeply nested structures

### GraphQL Variable Fuzzing Mode

- Only mutates the `variables` field
- **Type-aware payloads**:
  - Strings → string payloads
  - Integers → integer payloads
  - Floats → float payloads
  - Booleans → boolean payloads
  - Arrays → array payloads containing numbers and strings
  - Objects → nested object payloads with type-aware handling

---

## Installation

1. Open **Burp Suite**
2. Go to **Extensions → Extensions**
3. Click **Add**
4. Extension type: **Python**
5. Select `burp-json-graphql-type-fuzzer.py`
6. Ensure **Jython** is configured

---

## Usage

1. Right-click any request with a JSON or GraphQL body
2. Selects **Type Confusion** or **GraphQL** as appropriate

---

## Custom Payloads

Payloads are defined at the top of the extension
