"""Upload handlers applied to every multipart request (see FILE_UPLOAD_HANDLERS)."""
from django.core.files.uploadhandler import FileUploadHandler, SkipFile

from api.services.file_validation import max_file_size_bytes


class MaxSizeUploadHandler(FileUploadHandler):
    """
    Stops receiving a file as soon as it exceeds UPLOAD_MAX_FILE_SIZE_MB, instead of
    buffering it fully. The skipped file's name is recorded on the request so the
    view can answer 413 (see ``oversize_uploads``).
    """

    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
        self._received = 0
        self._limit = max_file_size_bytes()

    def receive_data_chunk(self, raw_data, start):
        self._received += len(raw_data)
        if self._received > self._limit:
            rejected = getattr(self.request, "_oversize_uploads", None)
            if rejected is None:
                rejected = []
                setattr(self.request, "_oversize_uploads", rejected)
            if self.file_name not in rejected:
                rejected.append(self.file_name)
            raise SkipFile()
        return raw_data

    def file_complete(self, file_size):
        return None


def oversize_uploads(request) -> list:
    """Names of files dropped by MaxSizeUploadHandler for this request (DRF or Django request)."""
    django_request = getattr(request, "_request", request)
    return list(getattr(django_request, "_oversize_uploads", []) or [])
