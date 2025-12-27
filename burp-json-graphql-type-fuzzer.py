from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from javax.swing import JMenuItem
import json
import threading
from copy import deepcopy
from collections import OrderedDict


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JSON Type Confusion")
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu_item = JMenuItem(
            "Send to Type Confusion", actionPerformed=self.start_background_task
        )
        return [menu_item]

    def start_background_task(self, event):
        thread = threading.Thread(target=self.modify_and_resend)
        thread.start()

    def modify_and_resend(self):
        for request_response in self._invocation.getSelectedMessages():
            request_info = self._helpers.analyzeRequest(request_response)
            body_bytes = request_response.getRequest()[request_info.getBodyOffset() :]
            body_str = body_bytes.tostring()

            try:
                json_data = json.loads(body_str, object_pairs_hook=OrderedDict)
                # print("Original JSON Data:", json_data)  # Debugging output
                modified_requests = self.generate_type_confusion_payloads(json_data)
                # print("Generated Payloads:", modified_requests)  # Debugging output
                for modified_body in modified_requests:
                    new_request = self._helpers.buildHttpMessage(
                        request_info.getHeaders(), json.dumps(modified_body).encode()
                    )
                    # print("Sending request with payload:", modified_body)  # Debugging output
                    self._callbacks.makeHttpRequest(
                        request_response.getHttpService(), new_request
                    )
            except Exception as e:
                print("Error in modify_and_resend:", str(e))  # Debugging output
                pass  # Ignore non-JSON bodies

    def generate_type_confusion_payloads(self, input_json):
        """
        Takes a JSON object and modifies each key's value one at a time with various types,
        including nested keys.
        """
        payloads = []

        # Define a set of unexpected values to replace with
        type_confusion_values = [
            12345,  # Integer
            12.345,  # Float
            "string_value",  # String
            "!\"$%&'()*+,-./:;<=>?@[]^_`{|}~#\\",  # Special characters
            [1, 2, 3],  # List
            {"nested": "object"},  # Object
            True,  # Boolean
            None,  # Null
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

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
