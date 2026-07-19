import re
from typing import Iterator, Dict, Any, List


# Inside ScanCode, we would import the official classes:
# from packagedcode.models import Package, Party, Dependency
# from packagedcode import DatafileHandler

class LinuxKernelModuleHandler:
    """
    DatafileHandler for compiled Linux Kernel Modules (.ko binaries).
    Extracts the .modinfo section and maps it to ScanCode's standard PackageData.
    """
    # Matches any Linux Kernel Object binary
    file_wildcards = ['*.ko']

    @classmethod
    def parse(cls, location: str) -> Iterator[Any]:
        """
        Main entry point called by ScanCode when scanning directories.
        """
        raw_metadata = cls.extract_modinfo(location)
        if not raw_metadata:
            return

        yield cls.build_package(raw_metadata)

    @staticmethod
    def extract_modinfo(location: str) -> Dict[str, Any]:
        """
        Reads the .modinfo byte section from the ELF file in-memory.
        Uses pyelftools (which is already a ScanCode dependency).
        """
        from elftools.elf.elffile import ELFFile

        metadata: Dict[str, Any] = {}

        try:
            with open(location, 'rb') as f:
                elffile = ELFFile(f)

                # Locate the specific .modinfo section in the ELF structure
                modinfo_sec = elffile.get_section_by_name('.modinfo')
                if not modinfo_sec:
                    return {}

                # Extract the raw binary block
                raw_bytes = modinfo_sec.data()

            # Split null-terminated bytes on \x00
            entries = [e.decode('utf-8', errors='ignore') for e in raw_bytes.split(b'\x00') if e]

            # Parse 'key=value' pairs safely
            for entry in entries:
                if '=' in entry:
                    key, val = entry.split('=', 1)

                    # Accumulate arrays for duplicate keys like 'alias' or 'depends'
                    if key in metadata:
                        if isinstance(metadata[key], list):
                            metadata[key].append(val)
                        else:
                            metadata[key] = [metadata[key], val]
                    else:
                        metadata[key] = val

        except Exception:
            # Return empty if the ELF is corrupted or not a valid LKM
            pass

        return metadata

    @classmethod
    def build_package(cls, metadata: Dict[str, Any]) -> Any:
        """
        Maps raw .modinfo dictionary keys into ScanCode's standard PackageData models.
        """
        # 1. Map Authors to standard 'Party' objects
        parties = []
        raw_author = metadata.get("author")
        if raw_author:
            authors = [a.strip() for a in re.split(r',|;', raw_author) if a.strip()]
            for author in authors:
                parties.append(
                    Party(
                        type="person",
                        name=author,
                        role="author"
                    )
                )

        # 2. Map 'depends' to standard 'Dependency' objects
        dependencies = []
        raw_depends = metadata.get("depends")
        if raw_depends:
            if isinstance(raw_depends, list):
                depends_list = raw_depends
            else:
                depends_list = [d.strip() for d in raw_depends.split(",") if d.strip()]

            for dep in depends_list:
                dependencies.append(
                    Dependency(
                        ref_requirement=dep
                    )
                )

        # 3. Construct and return ScanCode's official Package object
        return Package(
            type="linux-kernel-module",
            name=metadata.get("description", "Unknown Linux Kernel Driver"),
            version=metadata.get("version") or metadata.get("srcversion"),
            description=metadata.get("description"),
            declared_license=metadata.get("license"),
            parties=parties,
            dependencies=dependencies,
            # Store the raw dictionary under custom data for debugging
            api_data=metadata
        )