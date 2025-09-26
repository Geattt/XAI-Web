import os, math, hashlib, zipfile, rarfile, pefile

# ---------- Helper Functions ----------

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

def is_pe_file(filepath):
    try:
        pefile.PE(filepath)
        return True
    except:
        return False

def extract_features(pe, filepath):
    features = {}
    features["md5"] = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
    features["Machine"] = pe.FILE_HEADER.Machine
    features["SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
    features["Characteristics"] = pe.FILE_HEADER.Characteristics
    features["MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    features["MinorLinkerVersion"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    features["SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
    features["SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    features["SizeOfUninitializedData"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    features["AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    features["BaseOfCode"] = pe.OPTIONAL_HEADER.BaseOfCode
    features["BaseOfData"] = getattr(pe.OPTIONAL_HEADER, "BaseOfData", 0)
    features["ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
    features["SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment
    features["FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment
    features["MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    features["MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    features["MajorImageVersion"] = pe.OPTIONAL_HEADER.MajorImageVersion
    features["MinorImageVersion"] = pe.OPTIONAL_HEADER.MinorImageVersion
    features["MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    features["MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    features["SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
    features["SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders
    features["CheckSum"] = pe.OPTIONAL_HEADER.CheckSum
    features["Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    features["DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
    features["SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    features["SizeOfStackCommit"] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    features["SizeOfHeapReserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    features["SizeOfHeapCommit"] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    features["LoaderFlags"] = pe.OPTIONAL_HEADER.LoaderFlags
    features["NumberOfRvaAndSizes"] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Section info
    entropies, raws, virtuals = [], [], []
    for section in pe.sections:
        data = section.get_data()
        entropies.append(calculate_entropy(data))
        raws.append(section.SizeOfRawData)
        virtuals.append(section.Misc_VirtualSize)

    features["SectionsNb"] = len(pe.sections)
    features["SectionsMeanEntropy"] = round(sum(entropies)/len(entropies), 4) if entropies else 0
    features["SectionsMinEntropy"] = round(min(entropies), 4) if entropies else 0
    features["SectionsMaxEntropy"] = round(max(entropies), 4) if entropies else 0
    features["SectionsMeanRawsize"] = round(sum(raws)/len(raws), 4) if raws else 0
    features["SectionsMinRawsize"] = min(raws) if raws else 0
    features["SectionMaxRawsize"] = max(raws) if raws else 0
    features["SectionsMeanVirtualsize"] = round(sum(virtuals)/len(virtuals), 4) if virtuals else 0
    features["SectionsMinVirtualsize"] = min(virtuals) if virtuals else 0
    features["SectionMaxVirtualsize"] = max(virtuals) if virtuals else 0

    # Imports
    try:
        features["ImportsNbDLL"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        features["ImportsNb"] = sum([len(i.imports) for i in pe.DIRECTORY_ENTRY_IMPORT])
        features["ImportsNbOrdinal"] = sum([1 for i in pe.DIRECTORY_ENTRY_IMPORT for imp in i.imports if imp.name is None])
    except:
        features["ImportsNbDLL"] = 0
        features["ImportsNb"] = 0
        features["ImportsNbOrdinal"] = 0

    # Export
    try:
        features["ExportNb"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except:
        features["ExportNb"] = 0

    # Resources
    try:
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'directory'):
                    for res in entry.directory.entries:
                        if hasattr(res, 'directory'):
                            for r in res.directory.entries:
                                data_rva = r.data.struct.OffsetToData
                                size = r.data.struct.Size
                                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                resources.append((calculate_entropy(data), size))
        res_entropy = [x[0] for x in resources]
        res_sizes = [x[1] for x in resources]
        features["ResourcesNb"] = len(resources)
        features["ResourcesMeanEntropy"] = round(sum(res_entropy)/len(res_entropy), 4) if res_entropy else 0
        features["ResourcesMinEntropy"] = min(res_entropy) if res_entropy else 0
        features["ResourcesMaxEntropy"] = max(res_entropy) if res_entropy else 0
        features["ResourcesMeanSize"] = round(sum(res_sizes)/len(res_sizes), 4) if res_sizes else 0
        features["ResourcesMinSize"] = min(res_sizes) if res_sizes else 0
        features["ResourcesMaxSize"] = max(res_sizes) if res_sizes else 0
    except:
        features["ResourcesNb"] = 0
        features["ResourcesMeanEntropy"] = 0
        features["ResourcesMinEntropy"] = 0
        features["ResourcesMaxEntropy"] = 0
        features["ResourcesMeanSize"] = 0
        features["ResourcesMinSize"] = 0
        features["ResourcesMaxSize"] = 0

    features["LoadConfigurationSize"] = getattr(pe.OPTIONAL_HEADER, "LoadConfigurationSize", 0)
    features["VersionInformationSize"] = len(pe.FileInfo) if hasattr(pe, 'FileInfo') else 0

    return features
