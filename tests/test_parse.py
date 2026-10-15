"""Parser unit test on a tiny synthetic FastAPI project. Run: .venv/bin/python -m tests.test_parse"""
import pathlib, tempfile, textwrap
from ingest.parse_python import parse_repo


def build(tmp: pathlib.Path):
    (tmp / "app" / "routes").mkdir(parents=True)
    (tmp / "app" / "__init__.py").write_text("")
    (tmp / "app" / "routes" / "__init__.py").write_text(textwrap.dedent('''
        from fastapi import APIRouter
        from . import images
        prefix = "/v1"
        router = APIRouter(prefix="/api")
        router.include_router(images.router, prefix=prefix)
    '''))
    (tmp / "app" / "routes" / "images.py").write_text(textwrap.dedent('''
        from fastapi import APIRouter, UploadFile
        from app.services import thumbs
        router = APIRouter(prefix="/images")

        class Ctl:
            @router.post("/{id}")
            def upload(self, id: str, f: UploadFile):
                return thumbs.make(f)
    '''))
    (tmp / "app" / "services.py").write_text("")
    (tmp / "app" / "services").mkdir()
    (tmp / "app" / "services" / "__init__.py").write_text("")
    (tmp / "app" / "services" / "thumbs.py").write_text(textwrap.dedent('''
        from PIL import Image
        def make(f):
            return _resize(Image.open(f))
        def _resize(img):
            return img.resize((10, 10))
    '''))


def test():
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d); build(tmp)
        r = parse_repo(tmp, source_dirs=["app"])
        eps = {e["path"]: e for e in r.entrypoints}
        assert "/api/v1/images/{id}" in eps, eps                         # nested router prefixes resolved across files
        assert eps["/api/v1/images/{id}"]["method"] == "POST"
        calls = {(a.split(".")[-1], b.split(".")[-1]) for a, b, _ in r.calls}
        assert ("upload", "make") in calls and ("make", "_resize") in calls, calls   # module-alias and local call resolution
        uses = {(f.split(".")[-1], d_) for f, d_ in r.function_uses}
        assert ("make", "pillow") in uses, uses                            # PIL -> pillow distribution mapping
        assert ("upload", "python-multipart") in uses, uses                # implicit UploadFile -> python-multipart
        print("parser test: OK", f"({len(r.functions)} functions, {len(r.calls)} calls, {len(r.entrypoints)} entrypoints)")


if __name__ == "__main__":
    test()
