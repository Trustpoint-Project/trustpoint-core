"""Module that contains utilities to construct different archives from lists of bytes."""

from __future__ import annotations

import enum
import io
import tarfile
import zipfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Self


class ArchiveFormat(enum.Enum):
    """Supported archive formats."""

    mime_type: str
    file_extension: str

    ZIP = ('zip', 'application/zip', '.zip')
    TAR_GZ = ('tar_gz', 'application/gzip', '.tar.gz')

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> Self:
        """Extends the enum with a mime_type and file_extension.

        Args:
            value: The value to set.
            mime_type: The mime type to set.
            file_extension: The file extension to set.

        Returns:
            The constructed enum.
        """
        if value is None:
            err_msg = 'None is not a valid archive format.'

            raise ValueError(err_msg)
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


class Archiver:
    """Provides methods to construct different archives."""

    @staticmethod
    def archive_zip(data_to_archive: dict[str, bytes]) -> bytes:
        """Creates a zip-archive.

        Args:
            data_to_archive: Data to archive. Will use the key as the filename.

        Returns:
            The binary representation of the archive.
        """
        bytes_io = io.BytesIO()
        zip_file = zipfile.ZipFile(bytes_io, 'w')
        for file_name, bytes_blob in data_to_archive.items():
            zip_file.writestr(file_name, bytes_blob)
        zip_file.close()

        return bytes_io.getvalue()

    @staticmethod
    def archive_tar_gz(data_to_archive: dict[str, bytes]) -> bytes:
        """Creates a tar-gz-archive.

        Args:
            data_to_archive: Data to archive. Will use the key as the filename.

        Returns:
            The binary representation of the archive.
        """
        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for file_name, cert_bytes in data_to_archive.items():
                cert_io_bytes = io.BytesIO(cert_bytes)
                cert_io_bytes_info = tarfile.TarInfo(file_name)
                cert_io_bytes_info.size = len(cert_bytes)
                tar.addfile(cert_io_bytes_info, cert_io_bytes)

        return bytes_io.getvalue()

    @classmethod
    def archive(cls, data_to_archive: dict[str, bytes], archive_format: ArchiveFormat) -> bytes:
        """Creates an archive using the provided format.

        Args:
            data_to_archive: Data to archive. Will use the key as the filename.
            archive_format: The archive format to use.

        Returns:
            The binary representation of the archive.
        """
        if archive_format == ArchiveFormat.ZIP:
            return cls.archive_zip(data_to_archive)
        if archive_format == ArchiveFormat.TAR_GZ:
            return cls.archive_tar_gz(data_to_archive)
        err_msg = f'Unsupported archive format: {archive_format}.'
        raise ValueError(err_msg)
