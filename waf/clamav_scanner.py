try:
    import clamd
except Exception:
    clamd = None

cd = None
if clamd is not None:
    try:
        cd = clamd.ClamdUnixSocket()
        cd.ping()
    except Exception:
        try:
            cd = clamd.ClamdNetworkSocket()
            cd.ping()
        except Exception:
            cd = None


def scan_bytes(content: bytes):
    if not content or cd is None:
        return False, None
    try:
        res = cd.instream(content)
        for k, v in res.items():
            if isinstance(v, tuple) and v[0] == 'FOUND':
                return True, v[1]
        return False, None
    except Exception:
        return False, None
