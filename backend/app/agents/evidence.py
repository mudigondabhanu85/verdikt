import httpx


def format_request_raw(response: httpx.Response) -> str:
    request = response.request
    lines = [f"{request.method} {request.url.raw_path.decode()} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in request.headers.items()]
    try:
        content = request.content
    except httpx.RequestNotRead:
        # A multipart/streamed request (e.g. app.agents.file_upload's
        # file uploads) never gets its body eagerly buffered by httpx
        # the way a plain content= request does — .content is only
        # accessible after the request has actually been sent and read,
        # which the *response* we were handed doesn't guarantee for its
        # own .request. The headers above (including the multipart
        # boundary) are still real evidence; the raw body just isn't
        # reconstructable here.
        content = None
    if content:
        lines += ["", content.decode(errors="replace")]
    return "\n".join(lines)


def format_response_raw(response: httpx.Response) -> str:
    lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase}"]
    lines += [f"{k}: {v}" for k, v in response.headers.items()]
    body = response.text
    if len(body) > 4000:
        body = body[:4000] + "\n... (truncated)"
    return "\n".join(lines) + "\n\n" + body
