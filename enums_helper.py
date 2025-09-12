"""
Author: Milankovo, 2025
License: MIT
"""

import idaapi
import logging

logger = logging.getLogger("EnumsHelper")
logger.setLevel(logging.INFO)


NETNODE_NAME = "$ enums_helper"
last_enum_used: str | None = None

vvv = 0


class EnumChooser(idaapi.Choose):
    def __init__(self, title="Please choose enum", value=0):
        self.value = value
        super().__init__(
            title,
            cols=[["Enumeration", 30], ["Member", 30]],
            flags=idaapi.Choose.CH_MODAL,
        )
        self.items = self._get_enum_list()

    def _get_enum_list(self):
        enums = [("<NEW>", "<NEW>")]

        for i in range(1, idaapi.get_ordinal_limit()):
            if not idaapi.is_type_choosable(None, i):  # type: ignore
                continue

            t = idaapi.tinfo_t(ordinal=i)
            if not t.is_enum():
                continue
            name = t.get_type_name()
            if not name:
                logger.debug(f"Skipping unnamed enum with ordinal {i}: {t.dstr()}")
                continue

            idx, item = t.get_edm_by_value(self.value)

            if idx == -1:
                member = "<NEW>"
            else:
                member = item.name

            enums.append((name, member))
        return enums

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        return self.items[n][0]

    def OnRefresh(self, n):
        self.items = self._get_enum_list()
        return len(self.items)


def ask_new_enum() -> idaapi.tinfo_t | None:
    new_enum_name = idaapi.ask_ident("", "Enter new enum name:")
    if not new_enum_name:
        logger.warning("No name provided for the new enumeration. Operation aborted.")
        return None

    tid = idaapi.create_enum_type(
        new_enum_name, idaapi.enum_type_data_t(), 0, idaapi.no_sign, False
    )
    if tid == idaapi.BADADDR:
        logger.error(
            f"Error: Unable to create a new enumeration named '{new_enum_name}'."
        )
        return None

    return idaapi.tinfo_t(tid=tid)


def choose_or_create_enum(value: int):
    chooser = EnumChooser(value=value)
    selected = chooser.Show(modal=True)
    if selected < 0:
        return None

    selected_enum_name = chooser.items[selected][0]
    if selected_enum_name == "<NEW>":
        return ask_new_enum()
    else:
        return idaapi.tinfo_t(name=selected_enum_name)


class base_action_handler_t(idaapi.action_handler_t):
    action_name: str
    action_label: str
    action_shortcut: str

    @classmethod
    def register(cls: type["base_action_handler_t"]):
        action = idaapi.action_desc_t(
            cls.action_name, cls.action_label, cls(), cls.action_shortcut
        )
        idaapi.register_action(action)

    @classmethod
    def unregister(cls: type["base_action_handler_t"]):
        idaapi.unregister_action(cls.action_name)

    @classmethod
    def register_actions(cls: type["base_action_handler_t"]):
        for action in cls.__subclasses__():
            action.register()

    @classmethod
    def unregister_actions(cls: type["base_action_handler_t"]):
        for action in cls.__subclasses__():
            action.unregister()


def make_enum(nf: idaapi.number_format_t, enum_name: str):
    shift = idaapi.get_operand_type_shift(ord(nf.opnum))
    mask = 0xF << shift
    enum = 0x8 << shift
    nf.flags = (nf.flags & ~mask) | enum
    nf.type_name = enum_name


def dump_user_numforms(vu):
    for f, s in vu.cfunc.numforms.items():
        logger.info(
            f"found user numform ({f.ea:x}, {f.opnum}) ({ord(s.opnum)}, {s.flags:x}, {s.type_name})"
        )


def update_number_formats(
    cfunc: idaapi.cfuncptr_t, ea: int, nf: idaapi.number_format_t
):
    # very annoying idapython feature
    opnum = nf.opnum
    if isinstance(opnum, str):
        opnum = ord(opnum)

    loc = idaapi.operand_locator_t(ea, opnum)

    if loc in cfunc.numforms:  # type: ignore
        del cfunc.numforms[loc]  # type: ignore
    cfunc.numforms[loc] = nf  # type: ignore

    cfunc.save_user_numforms()


def add_enum_member(ti: idaapi.tinfo_t, v: int) -> bool:
    idx, edm = ti.get_edm_by_value(v)

    if idx != -1:
        logger.info(
            f"Using existing enum member '{edm.name}' at index {idx} with value {edm.value}."
        )
        return True

    new_name = idaapi.ask_ident(
        f"val_{v}",
        f"Name for new enum member of {ti.get_type_name()}",
    )

    if not new_name:
        logger.warning("No name provided for the new enum member. Operation aborted.")
        return False
    try:
        ti.add_edm(new_name, v)
    except ValueError as e:
        logger.error(f"Error: Failed to add the enum member. {e}")
        return False
    return True


def is_number(ctx: idaapi.action_ctx_base_t):
    if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
        return idaapi.AST_DISABLE_FOR_WIDGET

    vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
    if vu is None:
        return idaapi.AST_DISABLE
    vu.get_current_item(idaapi.USE_KEYBOARD)

    num = vu.get_number()
    if num is None:
        return idaapi.AST_DISABLE
    if num.nf.is_enum():
        return idaapi.AST_DISABLE
    return idaapi.AST_ENABLE


def update_enum_member(ti: idaapi.tinfo_t, num: idaapi.cnumber_t, vu: idaapi.vdui_t):
    if not add_enum_member(ti, num._value):
        return

    global last_enum_used
    last_enum_used = ti.get_type_name()

    make_enum(num.nf, last_enum_used)

    update_number_formats(vu.cfunc, vu.item.e.ea, num.nf)
    vu.item.e.type = ti

    # dump_user_numforms(vu)

    # vu.refresh_ctext(False)
    vu.cfunc.refresh_func_ctext()


class add_number_to_enum_action_handler_t(base_action_handler_t):
    action_name = "milankovo:add_number_to_enum"
    action_label = "Add number to enum"
    action_shortcut = "a"

    def activate(self, ctx: idaapi.action_ctx_base_t):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        num: idaapi.cnumber_t = vu.get_number()

        if num is None:
            return 0

        ti = choose_or_create_enum(num._value)
        if ti is None:
            logger.warning("No enumeration selected. Please try again.")
            return 0

        update_enum_member(ti, num, vu)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        return is_number(ctx)


class add_number_to_last_enum_action_handler_t(base_action_handler_t):
    action_name = "milankovo:add_number_to_last_enum"
    action_label = "Add number to the last used enum"
    action_shortcut = "shift-a"

    def activate(self, ctx: idaapi.action_ctx_base_t):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        num: idaapi.cnumber_t = vu.get_number()

        if num is None:
            return 0

        global last_enum_used
        ti = idaapi.tinfo_t(name=last_enum_used)
        if ti is None:
            logger.warning("No enumeration selected. Please try again.")
            return 0

        update_enum_member(ti, num, vu)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        global last_enum_used
        if last_enum_used is None:
            return idaapi.AST_DISABLE
        if len(last_enum_used) == 0:
            last_enum_used = None
            return idaapi.AST_DISABLE
        try:
            ti = idaapi.tinfo_t(name=last_enum_used)
            if not ti.is_enum():
                last_enum_used = None
                return idaapi.AST_DISABLE
        except ValueError:
            last_enum_used = None
            return idaapi.AST_DISABLE
        idaapi.update_action_label(
            self.action_name, f"Add number to enum '{last_enum_used}'"
        )
        return is_number(ctx)


class rename_enum_member_action_handler_t(base_action_handler_t):
    action_name = "milankovo:rename_enum_member"
    action_label = "Rename enum member"
    action_shortcut = "n"

    def activate(self, ctx: idaapi.action_ctx_base_t):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        parent = idaapi.tinfo_t()
        idx: int = vu.item.get_edm(parent)
        if idx == -1:
            return 0

        (idx2, edm) = parent.get_edm(idx)

        if idx2 == -1:
            old_name = "???"
        else:
            old_name = edm.name

        new_name = idaapi.ask_str(old_name, idaapi.HIST_IDENT, "New name:")
        if not new_name:
            return 0
        parent.rename_edm(idx, new_name, idaapi.ETF_FORCENAME)
        # vu.refresh_ctext(False)
        vu.cfunc.refresh_func_ctext()
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_DISABLE_FOR_WIDGET

        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        parent = idaapi.tinfo_t()
        idx: int = vu.item.get_edm(parent)
        if idx == -1:
            return idaapi.AST_DISABLE
        return idaapi.AST_ENABLE


class EnumsHelperPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = ""
    help = ""
    wanted_name = "enums helper"

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        load_last_enum_used()

        addon = idaapi.addon_info_t()
        addon.id = "milankovo.enums_helper"
        addon.name = "enums helper"
        addon.producer = "Milánek"
        addon.url = "https://github.com/milankovo/ida_enums_helper"
        addon.version = "1.0.0"
        idaapi.register_addon(addon)

        base_action_handler_t.register_actions()

        # Initialize and hook EnumsHelperHooks
        self.hooks = EnumsHelperHooks()
        self.hooks.hook()

        return idaapi.PLUGIN_KEEP

    def term(self):
        base_action_handler_t.unregister_actions()

        # Unhook EnumsHelperHooks
        if hasattr(self, "hooks"):
            self.hooks.unhook()

        save_last_enum_used()

    def run(self, arg):
        pass


class EnumsHelperHooks(idaapi.Hexrays_Hooks):
    def __init__(self):
        super().__init__()

    def populating_popup(self, widget, phandle, vu):
        # Attach actions to the popup menu
        idaapi.attach_action_to_popup(
            vu.ct, None, add_number_to_enum_action_handler_t.action_name
        )
        idaapi.attach_action_to_popup(
            vu.ct, None, add_number_to_last_enum_action_handler_t.action_name
        )
        idaapi.attach_action_to_popup(
            vu.ct, None, rename_enum_member_action_handler_t.action_name
        )
        return 0


def PLUGIN_ENTRY():
    return EnumsHelperPlugin()


def save_last_enum_used():
    logger.debug("Saving last_enum_used")
    global last_enum_used
    if not last_enum_used:
        return

    n = idaapi.netnode()
    if not n.create(NETNODE_NAME):
        logger.debug("netnode exists, clearing")
        n.kill()
        n.create(NETNODE_NAME)

    n = idaapi.netnode(NETNODE_NAME, 0, True)
    n.setblob(last_enum_used.encode(), 0, "I")
    logger.debug(f"Saved last_enum_used: {last_enum_used}")


def load_last_enum_used():
    global last_enum_used
    logger.debug("Loading last_enum_used")
    n = idaapi.netnode(NETNODE_NAME, 0, False)
    v = n.getblob(0, "I")
    if not v:
        logger.debug("netnode load failed or does not exist")
        return

    last_enum_used = v.decode()
    logger.debug(f"Loaded last_enum_used: {last_enum_used}")
