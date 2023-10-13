#!/bin/python
import os
import struct
import argparse

from zipfile import ZipFile, BadZipFile
from io import BufferedReader, BytesIO
from typing import Optional


class BadCrx(IOError):
    pass


class CrxArchive:


    def __init__(self, crx_path: str) -> None:
        self.crx_path = crx_path


    def get_zip_archive(self) -> Optional[ZipFile]:
        """Read CRX file and parse its content to ZIP format."""
        with open(self.crx_path, "rb") as crx_file:
            try:
                self.strip_crx_headers(crx_file)
                zip_file = ZipFile(
                    BytesIO(crx_file.read())
                )

            except (BadZipFile, BadCrx):
                return None

        return zip_file
    

    @staticmethod
    def assert_magic_number(crx_bytes:bytes) -> None:
        """Ensure there is a static string at the beginning of file."""
        magic_number = crx_bytes.decode("utf-8")
        if magic_number != "Cr24":
            raise BadCrx(f"'Unexpected magic number: {magic_number}.")


    @staticmethod
    def get_crx_version(crx_bytes:bytes) -> int:
        # extract an integer from bytes following little-endian order
        return struct.unpack("<I", crx_bytes)[0]


    @staticmethod
    def strip_crx2(crx_file:BufferedReader) -> None:
        """Strip headers for CRXv2 extension."""
        public_key_length_bytes = crx_file.read(4)
        signature_length_bytes = crx_file.read(4)

        public_key_length = struct.unpack("<I", public_key_length_bytes)[0]
        signature_length = struct.unpack("<I", signature_length_bytes)[0]

        crx_file.seek(public_key_length, signature_length, os.SEEK_CUR)


    @staticmethod
    def strip_crx3(crx_file:BufferedReader) -> None:
        """Strip headers for CRXv3 extension."""
        header_length_bytes = crx_file.read(4)
        header_length = struct.unpack("<I", header_length_bytes)[0]

        crx_file.seek(header_length, os.SEEK_CUR)


    @classmethod
    def strip_crx_headers(cls, crx_file:BufferedReader) -> None:
        """Strip headers from CRX file converting it to ZIP-encoded buffer"""
        magic_number_bytes = crx_file.read(4)
        version_bytes = crx_file.read(4)

        cls.assert_magic_number(magic_number_bytes)
        if cls.get_crx_version(version_bytes) <= 2:
            cls.strip_crx2(crx_file)
        else:
            cls.strip_crx3(crx_file)


    def extract_to_folder(self, target_path: str) -> None:
        """Extract the contents of the CRX file to a specified folder path."""
        zip_file = self.get_zip_archive()

        if zip_file is not None:
            os.makedirs(target_path, exist_ok=True)
            zip_file.extractall(target_path)
        else:
            raise BadCrx


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract a CRX file to a folder.')
    parser.add_argument('-p', '--path', help='Path to the CRX file.', type=str)
    args = parser.parse_args()

    crx_path = args.path
    while crx_path is None or not os.path.isfile(crx_path):
        crx_path = input("Please enter the path to the CRX file: ")

    crx_dir = os.path.dirname(crx_path)
    crx_fullname = os.path.basename(crx_path)
    crx_name = os.path.splitext(crx_fullname)[0]

    crx_file = CrxArchive(crx_path)
    target_path = os.path.join(crx_dir, crx_name)

    try:
        crx_file.extract_to_folder(target_path)
    except BadCrx:
        print("Error: the provided CRX archive cannot be extracted.")