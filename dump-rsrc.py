import pefile
import sys

def run(filename):
    dump = pefile.Dump()
    pe = pefile.PE(filename)
    encoding = 'utf-8'

    dump.add_header("Resource directory")
    dump.add_lines(pe.DIRECTORY_ENTRY_RESOURCE.struct.dump())

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.name is not None:
            name = res_type.name.decode(encoding, "backslashreplace_")
            dump.add_line(f"Name: [{name}]", 2,)
        else:
            res_type_id = pefile.RESOURCE_TYPE.get(res_type.struct.Id, "-")
            dump.add_line(f"Id: [0x{res_type.struct.Id:X}] ({res_type_id})", 2,)

        dump.add_lines(res_type.struct.dump(), 2)
        if hasattr(res_type, "directory"):
            dump.add_lines(res_type.directory.struct.dump(), 4)
            for resource_id in res_type.directory.entries:
                if resource_id.name is not None:
                    # use this for filename
                    name = resource_id.name.decode("utf-8", "backslashreplace_")
                    dump.add_line(f"Name: [{name}]", 6,)
                else:
                    dump.add_line(f"Id: [0x{resource_id.struct.Id:X}]", 6)

                dump.add_lines(resource_id.struct.dump(), 6)

                if hasattr(resource_id, "directory"):
                    dump.add_lines(resource_id.directory.struct.dump(), 8)
                    for resource_lang in resource_id.directory.entries:
                        if hasattr(resource_lang, "data"):
                            dump.add_line(
                                "\\--- LANG [%d,%d][%s,%s]"
                                % (
                                    resource_lang.data.lang,
                                    resource_lang.data.sublang,
                                    pefile.LANG.get(
                                        resource_lang.data.lang, "*unknown*"
                                    ),
                                    pefile.get_sublang_name_for_lang(
                                        resource_lang.data.lang, 
                                        resource_lang.data.sublang,
                                    ), ), 8,)
                            dump.add_lines(resource_lang.struct.dump(), 10)
                            dump.add_lines(resource_lang.data.struct.dump(), 12)
                            with open('resource-dump/%s' % name, 'wb') as f:
                                offset = resource_lang.data.struct.OffsetToData
                                length = resource_lang.data.struct.Size
                                f.write(pe.get_data(offset, length))
                    if (hasattr(resource_id.directory, "strings") and resource_id.directory.strings):
                        dump.add_line("[STRINGS]", 10)
                        for idx, res_string in list(sorted(resource_id.directory.strings.items())):
                            dump.add_line(
                                "{0:6d}: {1}".format(
                                    idx,
                                    res_string.encode(
                                        "unicode-escape", "backslashreplace"
                                    ).decode("ascii"),
                                ), 12,)

        dump.add_newline()
    dump.add_newline()

    with open('report.txt', 'w') as f:
        f.write(dump.get_text())

if __name__ == '__main__':
    run(sys.argv[1])