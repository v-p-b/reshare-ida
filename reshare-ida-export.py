import logging
import json
import os
import sys

from ida_typeinf import (
    tinfo_t,
    get_idati,
    tinfo_visitor_t,
    TVST_DEF,
    type_mods_t,
    udt_type_data_t,
    udm_t, array_type_data_t,
)
from ida_nalt import get_input_file_path, retrieve_input_file_md5
from reshare import *
from reshare.helpers import *

# -----------------------------------------------------------------------------

LOG_FILE = None
EXPORT_PATH = "/tmp/reshare.json"

# -----------------------------------------------------------------------------

RESH_TYPE_CACHE: dict[str, ReshDataType] = {}
UNK_ID = 0 # ID for unknown things

logger = logging.getLogger("pyghidra-export")

log_fmt = logging.Formatter("[%(levelname)s](%(asctime)s) %(message)s")
handlers = [
    logging.StreamHandler(sys.stdout),
]

if LOG_FILE is not None:
    handlers.append(logging.FileHandler(LOG_FILE))

logger.handlers.clear()
logger.setLevel(logging.DEBUG)
for h in handlers:
    h.setFormatter(log_fmt)
    h.setLevel(logging.DEBUG)
    logger.addHandler(h)

logger.info(f"Starting export {len(RESH_TYPE_CACHE)}...")


class ReshIDAException(Exception):
    pass


class tinfo_visitor(tinfo_visitor_t):
    def __init__(self):
        tinfo_visitor_t.__init__(self, TVST_DEF)

    def visit_type(self, out: type_mods_t, tif: tinfo_t, name: str, cmt: str) -> int:
        logger.info(f"{out} ; {tif.get_type_name()} ; {name} ; {cmt}")
        return 0


def _debug_object(o):
    for a in dir(o):
        if not a.startswith("is_"):
            continue
        method = getattr(o, a)
        try:
            x = method()
            logger.debug(f"{o} {a} = {x}")
        except TypeError:
            pass

def get_udt_members(T: tinfo_t) -> list[ReshStructureMemberPy]:
    global UNK_ID
    details = udt_type_data_t()
    ret: list[ReshStructureMemberPy] = []
    if not T.get_udt_details(details):
        raise ReshIDAException("Can't retrieve struct UDT details")
    for member in details:
        m: udm_t = member
        logger.info(f"  Member {T.get_type_name()}.{m.name}({m.size})") # Note: member unions have no name?
        resh_member_type = get_resh_data_type_from_ida(m.type)
        if resh_member_type is not None:
            m_name=m.name
            if len(m_name) == 0: # Unions don't have names!
                m_name="resh_member_%08X" % (UNK_ID)
                UNK_ID += 1
            # WARNING
            # If we move m out of this scope it gets all messed up!
            resh_member = ReshStructureMemberPy(
                name=m_name,
                type=resh_member_type.name,
                offset=int(int(m.offset)/8),  # Sizes are in bytes, offsets in bits?
            )
            ret.append(resh_member)
        else:
            raise ReshIDAException(f"Can't create member type for {T.name}.{m.name}")
    return ret

def get_resh_data_type_from_ida(T: tinfo_t) -> ReshDataType | None:
    global UNK_ID
    content: ReshDataTypeContent = ReshDataTypeContentPrimitivePy()

    #if isinstance(T, int):
    #    logger.error(f"Can't handle ints as types...")
    #    return None

    T_name: str = T.get_type_name()
    if T_name is None or len(T_name)==0:
        T_name = "resh_unk_%08X" % (UNK_ID,)
        UNK_ID += 1
    # if T_name=="PIRP":
    #    _debug_object(T)
    #    raise ReshIDAException("Debug exit")

    logger.info(f"{T_name} ({T.get_size()}) UDT: {T.is_udt()} Typedef: {T.is_typedef()} Typeref: {T.is_typeref()}")
    if T_name in RESH_TYPE_CACHE:
        return RESH_TYPE_CACHE[T_name]

    """
    if T.is_typedef() or T.is_typeref():
        logger.debug(f"Resolving typedef {T_name}")
        _debug_object(T)
        ref: tinfo_t|int = T.get_realtype(True)
        if isinstance(ref, int):
            logger.error(f"Fuck {T.get_type_name()}")

            ret = ReshDataType(name=T_name, size=int(T.get_size()), content=content, modifiers=[])
            return ret
            # We don't know what the fresh hell this is supposed to be, let's continue with a primitive type...
        else:
            logger.debug(f"Resolved to {ref.get_type()}")
            ret=get_resh_data_type_from_ida(ref)
            if ret is None:
                raise ReshIDAException(f"Can't resolve typedef ({T_name})!")
            RESH_TYPE_CACHE[T_name] = ret
            return ret
    """
    T_size = T.get_size()
    if T_size == 0x11111111: # Checking for -1
        # This usually indicates a typedef
        T_size = -1 # TODO should we use a different indicator value?

    ret = ReshDataType(name=T_name, size=int(T_size), content=None, modifiers=[])

    RESH_TYPE_CACHE[T_name] = ret

    if T.is_arithmetic():
        content = ReshDataTypeContentPrimitivePy()
    elif T.is_typedef():
        content = ReshDataTypeContentPrimitivePy()
    elif T.is_struct() or T.is_union():
        members=get_udt_members(T)
        if T.is_struct():
            content = ReshDataTypeContentStructurePy(members=members)
        else:
            content = ReshDataTypeContentUnionPy(members=members)
    elif T.is_array():
        array_details = array_type_data_t()
        if not T.get_array_details(array_details):
            raise ReshIDAException(f"Can't get array details for {T_name}")
        elem_type: tinfo_t = array_details.elem_type # IDAPython documentation is lies!
        logger.debug(f"ARRAY DETAILS: {T_name} {elem_type} {type(elem_type)}")
        elem_resh_type=get_resh_data_type_from_ida(elem_type)
        content = ReshDataTypeContentArrayPy(base_type=elem_resh_type.name, length=array_details.nelems)
    elif T.is_enum():
        pass  # TODO
    elif T.is_func():
        pass  # TODO
    elif T.is_ptr():
        base_type = T.get_pointed_object()
        base_resh_type = get_resh_data_type_from_ida(base_type)
        # if T_name == "PIRP":
        # logger.error(base_type)
        # _debug_object(base_type)
        # logger.error(base_resh_type)
        # raise ReshIDAException("Debug exit")
        if base_resh_type is not None:
            content = ReshDataTypeContentPointerPy(target_type=base_resh_type.name)
        else:
            raise ReshIDAException("Base type not found for pointer")
    else:
        _debug_object(T)
        #raise ReshIDAException("Unhandled type!")

    if content is None:
        logger.error(f"Couldn't create content for {T_name}")

    ret.content = content

    return ret


def get_data_types() -> list[ReshDataType]:
    type_info_lib = get_idati()
    ret = []
    for t in type_info_lib.named_types():
        t: tinfo_t = t
        logger.info(f"{t.get_final_type_name()}")
        get_resh_data_type_from_ida(t)
    for n, r in RESH_TYPE_CACHE.items():
        if r is not None:
            if r.content is None:
                raise ReshIDAException("????????")
            ret.append(r)
    return ret


export = ResharePy(
    project_name=os.path.basename(get_input_file_path()),
    target_md5=retrieve_input_file_md5().hex(),
)

# export.symbols.extend(get_function_symbols())
# export.data_types.extend([v for _, v in RESH_TYPE_CACHE.items()])
export.data_types.extend(get_data_types())

with open(EXPORT_PATH, "w") as out:
    out.write(json.dumps(export.to_json_data(), indent=2))

logger.info(f"{EXPORT_PATH} written ({len(RESH_TYPE_CACHE)})")
