from reshare import *
from ida_typeinf import *
from ida_domain import Database
from ida_domain.types import TypeDetails
from typing import Iterable
import json
import logging
import ida_idaapi

logger=logging.getLogger("reshare-ida-import")

# -------------------------------

IMPORT_PATH = "/tmp/reshare.json"
FUNC_SYM_IMPORT_ALLOW_RE: re.Pattern | None = None
FUNC_SYM_IMPORT_DENY_RE: re.Pattern | None = None
TYPE_IMPORT_ALLOW_RE: re.Pattern | None = None
TYPE_IMPORT_DENY_RE: re.Pattern | None = None

# -------------------------------

class ReshIDAException(Exception):
    pass

resh_data_types: dict[str, ReshDataType] ={}
ida_data_types: dict[str, tinfo_t] = {}

def get_ida_type_by_name(name: str) -> tinfo_t:
    if name in resh_data_types:
        return get_ida_type_from_resh_type(resh_data_types[name])
    else:
        raise ReshIDAException("Can't find data type '%s'" % (name,))

def get_ida_type_from_resh_type(resh_type: ReshDataType)->tinfo_t:
    type_name=resh_type.name.strip()
    #print(type_name)

    # We must give the type a name before caching, otherwise self-references will fail
    # Naturally, tinfo_t(name:str) doesn't name a new type but tries to look up one...
    ret : tinfo_t = tinfo_t()
    ret.get_named_type(None, type_name)
    print(ret.get_type_name())

    if type_name in ida_data_types:
        return ida_data_types[type_name]

    # This get_named_type() retrieves the tinfo_t from the default type info DB
    # ida_typeinf.get_named_type() on the other hand checks if a type exists
    # Type info is wrong too...
    local_tif: tinfo_t =get_idati().get_named_type(type_name) # type: ignore
    if local_tif is not None:
        ida_data_types[resh_type.name.strip()]=local_tif
        #print(local_tif, type(local_tif))
        return local_tif
    if resh_type.content.type == "PRIMITIVE":
        if resh_type.size == 1:
            ret.create_simple_type(BT_INT8)
        elif resh_type.size == 2:
            ret.create_simple_type(BT_INT16)
        elif resh_type.size == 4:
            ret.create_simple_type(BT_INT32)
        elif resh_type.size == 8:
            ret.create_simple_type(BT_INT64)
        else:
            atd=array_type_data_t(0,resh_type.size)
            ret.create_array(atd)
        ida_data_types[resh_type.name]=ret
    elif resh_type.content.type == "ARRAY":
        array_content: ReshDataTypeContentArray = resh_type.content # type:ignore
        ida_target_type=get_ida_type_by_name(array_content.base_type.type_name)
        #ret=tinfo_t(ida_target_type)
        atd = array_type_data_t()
        atd.base=0
        atd.nelems=array_content.length
        atd.elem_type=ida_target_type
        ret.create_array(atd)
        ida_data_types[resh_type.name] = ret
    elif resh_type.content.type == "POINTER":
        ptr_content: ReshDataTypeContentPointer = resh_type.content
        ida_data_types[type_name] = ret
        ida_target_type=get_ida_type_by_name(ptr_content.target_type.type_name)
        ret.create_ptr(ida_target_type)
        #print(ret, repr(ret.is_ptr()), ret.get_unpadded_size())
    elif resh_type.content.type=="ENUM":
        enum_content: ReshDataTypeContentEnum = resh_type.content # type: ignore
        ret.create_enum()
        ida_data_types[type_name] = ret
        #TODO
    elif resh_type.content.type=="UNION":
        #print(resh_type)
        union_content: ReshDataTypeContentUnion = resh_type.content # type: ignore
        udt = udt_type_data_t()
        udt.is_union = True
        for m in union_content.members:
            member_type=get_ida_type_by_name(m.type.type_name)
            udt_member=udt.add_member(m.name,member_type,m.offset)
            #print(udt_member.name, udt_member.offset, udt_member.size)
        if not ret.create_udt(udt, BTF_UNION):
            # TODO If we can't figure out union offsets we just return empty for now
            udt = udt_type_data_t()
            udt.is_union = True
            ret.create_udt(udt, BTF_UNION)
            #raise ReshIDAException("Can't create UDT for union '%s'" % (type_name))
        ida_data_types[type_name] = ret
    elif resh_type.content.type=="STRUCTURE":
        print(resh_type.name)
        struct_content: ReshDataTypeContentStructure = resh_type.content # type: ignore
        udt = udt_type_data_t()

        ida_data_types[type_name] = ret # Self-references!
        # IDA freaks out if offsets don't line up so we just add members in order and hope for the best
        for m in struct_content.members:
            member_type = get_ida_type_by_name(m.type.type_name)
            udt_member=udt.add_member(m.name, member_type)
            if udt_member is None:
                raise ReshIDAException("Can't add UDT member to struct '%s'" % (type_name,))
            #print(udt_member.name, udt_member.offset, udt_member.size)
        # Do as Romans do: we must check status codes to see where things go wrong
        # See also JPL #7
        if not ret.create_udt(udt):
            raise ReshIDAException("Can't create UDT for struct '%s'" % (type_name))
        #print("Added structure", ret)
    else:
        ida_data_types[type_name] = ret

    # Apparently this resets everything to a typedef
    #ret.get_named_type(None, type_name)
    return ret

def import_data_types(resh: Reshare):
    for dt in resh.data_types:
        resh_data_types[dt.name] = dt

    # ... IDA doesn't support transactions :P ...

    default_til=get_idati()
    for dt in resh.data_types:
        if (
            TYPE_IMPORT_ALLOW_RE is not None
            and TYPE_IMPORT_ALLOW_RE.fullmatch(dt.name) is None
        ) or (
            TYPE_IMPORT_DENY_RE is not None
            and TYPE_IMPORT_DENY_RE.fullmatch(dt.name) is not None
        ):
            continue
        logger.info("[*] Importing type", dt.name)
        try:
            ida_dt = get_ida_type_from_resh_type(dt)

            if ida_dt is not None:
                #res=ida_dt.save_type()
                res=ida_dt.set_named_type(default_til, dt.name)
                print("Saving", ida_dt.get_type_name(), res)

        except ReshIDAException as e:
            logger.error("[-] Couldn't import '%s' :(\n%s" % (dt.name, str(e)))

"""
def import_symbols(resh: Reshare):
    for sym in resh.symbols:
        sym_type = None
        if sym.type is not None:
            sym_type = get_ida_type_by_name(sym.type.type_name)
        if isinstance(sym_type, FunctionSignature):
            if (
                FUNC_SYM_IMPORT_ALLOW_RE is not None
                and FUNC_SYM_IMPORT_ALLOW_RE.fullmatch(sym.name) is None
            ) or (
                FUNC_SYM_IMPORT_DENY_RE is not None
                and FUNC_SYM_IMPORT_DENY_RE.fullmatch(sym.name) is not None
            ):
                continue
            f = getFunction(sym.name)
            if f is not None:
                logger.info("Applying function signature ", f.getName(), sym_type)
                cmd = ApplyFunctionSignatureCmd(
                    f.getEntryPoint(), sym_type, SourceType.USER_DEFINED
                )
                cmd.applyTo(currentProgram)
"""

def main():
    db = Database()
    print(f"IDA Data Types Size {len(ida_data_types)}")
    for t in db.types:
        ida_data_types[TypeDetails.from_tinfo_t(t).name]=t
    print(f"IDA Data Types Size {len(ida_data_types)}")
    with open(IMPORT_PATH, "r") as input_json:
        data = json.load(input_json)
        resh = Reshare.from_json_data(data)
        import_data_types(resh)
        #import_symbols(resh)
    print(f"IDA Data Types Size {len(ida_data_types)}")
    #print(repr(ida_data_types))


if __name__ == "__main__":
    main()
