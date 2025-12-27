# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from javax.swing import JMenuItem
import json
import threading
from copy import deepcopy
from collections import OrderedDict

# -------------------------
# Customize these payload lists
# -------------------------
STRING_PAYLOADS = [
    "",
    "string_value",
    "!\"$%&'()*+,-./:;<=>?@[]^_`{|}~#\\",
    "😀",
    "../../../../etc/passwd",
]

INT_PAYLOADS = [0, -1, 1, 2147483647, -2147483648, 999999999]

FLOAT_PAYLOADS = [0.0, -1.0, 3.14159, 1e6]

BOOL_PAYLOADS = [True, False]

ARRAY_PAYLOADS = [
    [],
    [1],
    ["a", "b"],
    ["!\"$%&'()*+,-./:;<=>?@[]^_`{|}~#\\"],
]

OBJECT_PAYLOADS = [
    {},
    {"boolean": True},
    {"string": "!\"$%&'()*+,-./:;<=>?@[]^_`{|}~#\\", "number": 0},
]

NULL_PAYLOADS = []
# -------------------------


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JSON Type Confusion / GraphQL Mutator")
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu_item_type_confusion = JMenuItem(
            "Send to Type Confusion", actionPerformed=self.start_background_task
        )
        menu_item_graphql = JMenuItem(
            "GraphQL (mutate variables)",
            actionPerformed=self.start_graphql_task,
        )
        return [menu_item_type_confusion, menu_item_graphql]

    def start_background_task(self, event):
        thread = threading.Thread(target=self.modify_and_resend)
        thread.start()

    def start_graphql_task(self, event):
        thread = threading.Thread(target=self.modify_and_resend_graphql)
        thread.start()

    def modify_and_resend(self):
        for request_response in self._invocation.getSelectedMessages():
            request_info = self._helpers.analyzeRequest(request_response)
            body_bytes = request_response.getRequest()[request_info.getBodyOffset() :]
            try:
                body_str = body_bytes.tostring()
            except Exception:
                body_str = str(body_bytes)

            try:
                json_data = json.loads(body_str, object_pairs_hook=OrderedDict)
                modified_requests = self.generate_type_confusion_payloads(json_data)
                for modified_body in modified_requests:
                    new_request = self._helpers.buildHttpMessage(
                        request_info.getHeaders(), json.dumps(modified_body).encode()
                    )
                    self._callbacks.makeHttpRequest(
                        request_response.getHttpService(), new_request
                    )
            except Exception:
                continue

    def modify_and_resend_graphql(self):
        for request_response in self._invocation.getSelectedMessages():
            request_info = self._helpers.analyzeRequest(request_response)
            body_bytes = request_response.getRequest()[request_info.getBodyOffset() :]
            try:
                body_str = body_bytes.tostring()
            except Exception:
                body_str = str(body_bytes)

            try:
                json_data = json.loads(body_str, object_pairs_hook=OrderedDict)
            except Exception:
                continue

            if "variables" not in json_data:
                continue

            variables = json_data["variables"]
            variables_is_string_encoded = False
            if isinstance(variables, str):
                try:
                    variables_parsed = json.loads(
                        variables, object_pairs_hook=OrderedDict
                    )
                    variables_is_string_encoded = True
                except Exception:
                    continue
            else:
                variables_parsed = variables

            if not isinstance(variables_parsed, dict):
                continue

            payloads = self.generate_graphql_variable_payloads(
                json_data, variables_parsed, variables_is_string_encoded
            )

            for payload in payloads:
                new_body_bytes = json.dumps(payload).encode()
                new_request = self._helpers.buildHttpMessage(
                    request_info.getHeaders(), new_body_bytes
                )
                self._callbacks.makeHttpRequest(
                    request_response.getHttpService(), new_request
                )

    def generate_type_confusion_payloads(self, input_json):
        payloads = []
        type_confusion_values = [
            12345,
            12.345,
            "string_value",
            "!\"$%&'()*+,-./:;<=>?@[]^_`{|}~#\\",
            [1, 2, 3],
            {"nested": "object"},
            True,
            None,
        ]

        def modify_json(obj, parent_keys=[]):
            if isinstance(obj, dict):
                for key in obj.keys():
                    for value in type_confusion_values:
                        modified_json = deepcopy(input_json)
                        target = modified_json
                        for parent in parent_keys:
                            target = target[parent]
                        target[key] = value
                        payloads.append(modified_json)
                    modify_json(obj[key], parent_keys + [key])
            elif isinstance(obj, list):
                for index, item in enumerate(obj):
                    modify_json(item, parent_keys + [index])

        modify_json(input_json)
        return payloads

    def generate_graphql_variable_payloads(
        self, full_json, variables_obj, variables_are_string_encoded
    ):
        """
        Collect candidates such that:
         - If a variable is an object or array, we include whole-object/whole-array replacements
           (using OBJECT_PAYLOADS / ARRAY_PAYLOADS) AND DO NOT recurse into that object/array.
         - If a variable is a primitive (string/int/float/bool/null), include primitive replacements.
        """
        payloads = []

        def set_by_path(obj, path, value):
            cur = obj
            for p in path[:-1]:
                cur = cur[p]
            cur[path[-1]] = value

        try:
            string_types = (basestring,)
        except NameError:
            string_types = (str,)

        def payloads_for_type(value):
            if isinstance(value, string_types):
                return STRING_PAYLOADS
            elif isinstance(value, bool):
                return BOOL_PAYLOADS
            elif type(value) is int:
                return INT_PAYLOADS
            elif isinstance(value, float):
                return FLOAT_PAYLOADS
            elif isinstance(value, list):
                return ARRAY_PAYLOADS
            elif isinstance(value, dict):
                return OBJECT_PAYLOADS
            elif value is None:
                return NULL_PAYLOADS
            else:
                return []

        # Collect top-level candidate paths. When encountering a dict/list, record it as a
        # whole-replace candidate and DO NOT recurse into its children.
        leaf_paths = []  # list of tuples (path, value, replace_whole_bool)

        def collect_top_level_candidates(obj, path):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, dict) or isinstance(v, list):
                        # record the child itself as a whole-replacement candidate and do NOT recurse into it
                        leaf_paths.append((path + [k], v, True))
                    else:
                        # primitive: record for primitive replacement
                        leaf_paths.append((path + [k], v, False))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, dict) or isinstance(item, list):
                        leaf_paths.append((path + [i], item, True))
                    else:
                        leaf_paths.append((path + [i], item, False))
            else:
                # shouldn't reach here for top-level variables (we only call on dict), but keep for completeness
                leaf_paths.append((path, obj, False))

        collect_top_level_candidates(variables_obj, [])

        # For each collected candidate, use appropriate payload list and produce full payloads
        for path, original_value, replace_whole in leaf_paths:
            candidates = payloads_for_type(original_value)
            if not candidates:
                continue

            for candidate in candidates:
                if candidate == original_value:
                    continue

                modified_full = deepcopy(full_json)
                if variables_are_string_encoded:
                    vars_parsed = json.loads(
                        modified_full["variables"], object_pairs_hook=OrderedDict
                    )
                    set_by_path(vars_parsed, path, deepcopy(candidate))
                    modified_full["variables"] = json.dumps(vars_parsed)
                else:
                    set_by_path(modified_full["variables"], path, deepcopy(candidate))

                payloads.append(modified_full)

        return payloads

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
