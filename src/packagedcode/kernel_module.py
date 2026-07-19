#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/scancode-toolkit for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from typing import Iterator, Dict, Any, List

# ==============================================================================
# LKM DatafileHandler Pseudocode Design
# ==============================================================================
# This handles locating the .modinfo section in compiled Linux Kernel Modules 
# (.ko ELF binaries) and mapping the extracted null-terminated key=value metadata
# cleanly into ScanCode's standard PackageData models.

class LinuxKernelModuleHandler:
    """
    DatafileHandler for compiled Linux Kernel Modules (.ko binaries).
    """
    file_wildcards = ['*.ko']
    
    @classmethod
    def parse(cls, location: str) -> Iterator[Any]:
        """
        Main entry point. Extracts .modinfo and yields mapped Package data.
        """
        raw_metadata = cls.extract_modinfo(location)
        if not raw_metadata:
            return
            
        yield cls.build_package(raw_metadata)

    @staticmethod
    def extract_modinfo(location: str) -> Dict[str, Any]:
        """
        Safely locates and extracts the .modinfo section from an ELF binary
        using the python-native pyelftools library.
        """
        from elftools.elf.elffile import ELFFile
        
        metadata: Dict[str, Any] = {}
        valid_keys = {"license", "description", "author", "srcversion", "version", "depends", "alias"}
        
        try:
            with open(location, 'rb') as f:
                elffile = ELFFile(f)
                
                # Locate the specific .modinfo section in the ELF binary
                modinfo_sec = elffile.get_section_by_name('.modinfo')
                if not modinfo_sec:
                    return {}
                
                # Extract the raw binary block from ONLY the .modinfo section
                raw_bytes = modinfo_sec.data()
            
            # Since .modinfo is null-separated, we split directly on the null byte (\x00)
            entries = [e.decode('utf-8', errors='ignore') for e in raw_bytes.split(b'\x00') if e]
            
            # Parse 'key=value' pairs safely from ONLY the extracted .modinfo entries
            for entry in entries:
                if '=' in entry:
                    key, val = entry.split('=', 1)
                    
                    if key in valid_keys:
                        # Accumulate values for keys that can appear multiple times (like alias or depends)
                        if key in metadata:
                            if isinstance(metadata[key], list):
                                metadata[key].append(val)
                            else:
                                metadata[key] = [metadata[key], val]
                        else:
                            metadata[key] = val
                        
        except Exception:
            # Return gracefully if the file is not a valid ELF binary
            pass
            
        return metadata

    @classmethod
    def build_package(cls, metadata: Dict[str, Any]) -> Any:
        """
        Normalizes raw .modinfo dictionary keys into ScanCode's standard PackageData models.
        """
        # 1. Normalize authors into standard Party models
        parties = []
        raw_author = metadata.get("author")
        if raw_author:
            # Handle multiple comma- or semicolon-separated authors safely
            authors = [a.strip() for a in re.split(r',|;', raw_author) if a.strip()]
            for author in authors:
                parties.append(
                    Party(
                        type="person",
                        name=author,
                        role="author"
                    )
                )
                
        # 2. Map 'depends' into standard DependentPackage models
        dependencies = []
        raw_depends = metadata.get("depends")
        if raw_depends:
            if isinstance(raw_depends, list):
                depends_list = raw_depends
            else:
                depends_list = [d.strip() for d in raw_depends.split(",") if d.strip()]
                
            for dep in depends_list:
                dependencies.append(
                    DependentPackage(
                        purl=PackageURL(type="linux-kernel-module", name=dep).to_string(),
                        scope='dependencies',
                        extracted_requirement=None,
                        is_runtime=True,
                        is_optional=False,
                    )
                )

        # 3. Construct and return ScanCode PackageData structure
        package_data = dict(
            datasource_id="linux_kernel_module",
            type="linux-kernel-module",
            name=metadata.get("description", "Unknown Linux Kernel Driver"),
            description=metadata.get("description"),
            version=metadata.get("version") or metadata.get("srcversion"),
            extracted_license_statement=metadata.get("license"),
            parties=parties,
            dependencies=dependencies,
        )
        return PackageData.from_data(package_data)
