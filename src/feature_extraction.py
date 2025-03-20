import pefile
import hashlib
import magic
import numpy as np
import os
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_file_type(file_path):
    return magic.Magic(mime=True).from_file(file_path)

def extract_pe_features(file_path):
    features = {}
    try:
        pe = pefile.PE(file_path)
        features["num_sections"] = len(pe.sections)
        features["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features["image_base"] = pe.OPTIONAL_HEADER.ImageBase
        features["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imports.append(imp.name.decode() if imp.name else "")
        features["imports"] = len(imports)
    except Exception:
        pass
    return features

def extract_opcode_features(file_path):
    try:
        with open(file_path, "rb") as f:
            binary_data = f.read()
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        opcodes = [insn.mnemonic for insn in cs.disasm(binary_data, 0x1000)]
        opcode_counts = {op: opcodes.count(op) for op in set(opcodes)}
        return opcode_counts
    except Exception:
        return {}

def extract_string_features(file_path, min_length=4):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
        return len(strings)
    except Exception:
        return 0

def extract_features(file_path):
    features = {}
    features["sha256"] = get_file_hash(file_path)
    features["file_type"] = get_file_type(file_path)
    if "pe" in features["file_type"]:
        features.update(extract_pe_features(file_path))
    features["num_strings"] = extract_string_features(file_path)
    features.update(extract_opcode_features(file_path))
    return features
