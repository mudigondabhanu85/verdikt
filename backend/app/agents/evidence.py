import httpx


def format_request_raw(response: httpx.Response) -> str:
    request = response.request
    lines = [f"{request.method} {request.url.raw_path.decode()} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in request.headers.items()]
    if request.content:
        lines += ["", request.content.decode(errors="replace")]
    return "\n".join(lines)


def format_response_raw(response: httpx.Response) -> str:
    lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase}"]
    lines += [f"{k}: {v}" for k, v in response.headers.items()]
    body = response.text
    if len(body) > 4000:
        body = body[:4000] + "\n... (truncated)"
    return "\n".join(lines) + "\n\n" + body
