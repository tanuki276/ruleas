"""Bound HTTP input before parsing and keep a bounded compiled-policy cache."""
import json
from collections import OrderedDict
from threading import Lock
from fastapi.responses import JSONResponse
from rulea import RuleEngine

MAX_BODY = 1048576
MAX_CONTEXT = 65536

class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            total += len(message.get('body', b''))
            if total > MAX_BODY:
                return await JSONResponse({'detail': 'Request body exceeds 1 MiB'}, status_code=413)(scope, receive, send)
            chunks.append(message.get('body', b''))
            if not message.get('more_body', False):
                break
        body = b''.join(chunks)
        # Bound JSON nesting before the framework's JSON decoder can recurse.
        depth, quoted, escaped = 0, False, False
        for byte in body:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > 64:
                    return await JSONResponse({'detail': 'JSON body exceeds nesting depth 64'}, status_code=422)(scope, receive, send)
            elif byte in (93, 125):
                depth -= 1
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return await receive()
        await self.app(scope, bounded_receive, send)

class EngineCache:
    def __init__(self, capacity=32):
        self.capacity = capacity
        self.entries = OrderedDict()
        self.lock = Lock()

    def get(self, policy):
        key = (policy.id, policy.version)
        with self.lock:
            cached = self.entries.get(key)
            if cached is not None:
                self.entries.move_to_end(key)
                return cached
        # Compile without holding the cache lock; evaluations never hold this lock.
        compiled = RuleEngine.from_string(policy.source)
        with self.lock:
            cached = self.entries.setdefault(key, compiled)
            self.entries.move_to_end(key)
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)
            return cached

def validate_context(value):
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 4096:
            raise ValueError('context exceeds depth 32 or 4096 nodes')
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')) > MAX_CONTEXT:
        raise ValueError('context exceeds 64 KiB')
    return value
