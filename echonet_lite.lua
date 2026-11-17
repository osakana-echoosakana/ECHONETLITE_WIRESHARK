--[[
  ECHONET Lite dissector for Wireshark (Lua)

  - UDP port 3610 (default, changeable in Preferences)
  - EHD1 / EHD2 / TID
  - SEOJ / DEOJ (class group / class / instance, with names)
  - ESV (with names), including the two OPC sections of SetGet / SetGet_Res / SetGet_SNA
  - OPC / EPC / PDC / EDT with names and decoded values.
    When the ECHONET Consortium's Machine Readable Appendix (MRA) is installed
    (see below), property names and value definitions of APPENDIX Release A .. R
    are read from it at start-up. The MRA itself is not bundled with this plugin.
    Without the MRA, built-in tables with the most common names are used.
  - Japanese / English display (Preferences > Protocols > ECHONET Lite)

  Install: copy this file into Wireshark's personal Lua plugins folder
  (Help > About Wireshark > Folders > "Personal Lua Plugins") and restart.

  License: MIT
]]

local PLUGIN_VERSION = "1.1.0"

set_plugin_info({
    version     = PLUGIN_VERSION,
    description = "ECHONET Lite dissector",
    author      = "ECHONET Lite with Wireshark project",
    repository  = "https://github.com/osakana-echoosakana/ECHONETLITE_WIRESHARK",
})

local el = Proto("echonetlite", "ECHONET Lite")

---------------------------------------------------------------------------
-- Machine Readable Appendix (MRA) loader
--
-- The MRA is NOT bundled with this plugin. Download it from the ECHONET
-- Consortium web site, unpack it, and put it in one of these folders
-- (or set "MRA folder" in Preferences > Protocols > ECHONET Lite):
--   <Personal configuration folder>/echonet_mra
--   <Personal Lua plugins folder>/echonet_mra
-- The folder must contain metaData.json, definitions/, devices/,
-- superClass/ and nodeProfile/ (a "mraData" sub-folder is also accepted).
---------------------------------------------------------------------------

-- Minimal JSON decoder (objects -> tables, arrays -> sequences, null -> nil)
local json_decode
do
    local function utf8_char(c)
        if c < 0x80 then return string.char(c)
        elseif c < 0x800 then
            return string.char(0xC0 + math.floor(c / 0x40), 0x80 + c % 0x40)
        elseif c < 0x10000 then
            return string.char(0xE0 + math.floor(c / 0x1000), 0x80 + math.floor(c / 0x40) % 0x40, 0x80 + c % 0x40)
        end
        return string.char(0xF0 + math.floor(c / 0x40000), 0x80 + math.floor(c / 0x1000) % 0x40,
                           0x80 + math.floor(c / 0x40) % 0x40, 0x80 + c % 0x40)
    end
    local ESC = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

    json_decode = function(s)
        local pos = 1
        local function ws() pos = s:find("[^ \t\r\n]", pos) or (#s + 1) end
        local function err(msg) error(string.format("JSON error at %d: %s", pos, msg), 0) end
        local value
        local function str()
            pos = pos + 1
            local buf = {}
            while true do
                local i = s:find('["\\]', pos)
                if not i then err("unterminated string") end
                buf[#buf + 1] = s:sub(pos, i - 1)
                if s:sub(i, i) == '"' then pos = i + 1; break end
                local e = s:sub(i + 1, i + 1)
                if e == "u" then
                    local c = tonumber(s:sub(i + 2, i + 5), 16) or 0x3F
                    pos = i + 6
                    if c >= 0xD800 and c <= 0xDBFF and s:sub(pos, pos + 1) == "\\u" then
                        local lo = tonumber(s:sub(pos + 2, pos + 5), 16) or 0xDC00
                        c = 0x10000 + (c - 0xD800) * 0x400 + (lo - 0xDC00)
                        pos = pos + 6
                    end
                    buf[#buf + 1] = utf8_char(c)
                else
                    buf[#buf + 1] = ESC[e] or e
                    pos = i + 2
                end
            end
            return table.concat(buf)
        end
        value = function()
            ws()
            local c = s:sub(pos, pos)
            if c == "{" then
                local t = {}
                pos = pos + 1; ws()
                if s:sub(pos, pos) == "}" then pos = pos + 1; return t end
                while true do
                    ws()
                    if s:sub(pos, pos) ~= '"' then err("expected key") end
                    local k = str()
                    ws()
                    if s:sub(pos, pos) ~= ":" then err("expected ':'") end
                    pos = pos + 1
                    t[k] = value()
                    ws()
                    local d = s:sub(pos, pos); pos = pos + 1
                    if d == "}" then return t end
                    if d ~= "," then err("expected ',' or '}'") end
                end
            elseif c == "[" then
                local t = {}
                pos = pos + 1; ws()
                if s:sub(pos, pos) == "]" then pos = pos + 1; return t end
                while true do
                    t[#t + 1] = value()
                    ws()
                    local d = s:sub(pos, pos); pos = pos + 1
                    if d == "]" then return t end
                    if d ~= "," then err("expected ',' or ']'") end
                end
            elseif c == '"' then
                return str()
            elseif s:sub(pos, pos + 3) == "true" then pos = pos + 4; return true
            elseif s:sub(pos, pos + 4) == "false" then pos = pos + 5; return false
            elseif s:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil
            else
                local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
                if not num or num == "" then err("unexpected character") end
                pos = pos + #num
                return tonumber(num)
            end
        end
        local v = value()
        return v
    end
end

local MRA = nil          -- loaded MRA (nil = not loaded, built-in tables are used)
local MRA_STATUS = ""    -- human readable load status
local MRA_LOADED_FROM = nil

local function read_file(path)
    local fh = io.open(path, "rb")
    if not fh then return nil end
    local data = fh:read("*a")
    fh:close()
    return data
end

local function read_json(path)
    local data = read_file(path)
    if not data then return nil end
    if data:sub(1, 3) == "\239\187\191" then data = data:sub(4) end -- UTF-8 BOM
    local ok, v = pcall(json_decode, data)
    if ok then return v end
    return nil, v
end

local function join(a, b)
    local sep = package.config:sub(1, 1)
    if a:sub(-1) == "/" or a:sub(-1) == "\\" then return a .. b end
    return a .. sep .. b
end

local function mra_props(list)
    local res = {}
    for _, p in ipairs(list or {}) do
        local epc = tonumber(p.epc)
        if epc then
            res[epc] = res[epc] or {}
            local vr = p.validRelease or {}
            local pn = p.propertyName or {}
            table.insert(res[epc], { from = vr.from or "A", to = vr.to or "latest",
                                     ja = pn.ja, en = pn.en, data = p.data or {} })
        end
    end
    return res
end

local function try_load_mra(dir)
    if not dir or dir == "" then return nil end
    if not read_file(join(dir, "metaData.json")) then
        local sub = join(dir, "mraData")
        if read_file(join(sub, "metaData.json")) then dir = sub else return nil end
    end
    local meta = read_json(join(dir, "metaData.json")) or {}
    meta = meta.metaData or meta
    local defs = read_json(join(join(dir, "definitions"), "definitions.json"))
    local sup = read_json(join(join(dir, "superClass"), "0x0000.json"))
    local node = read_json(join(join(dir, "nodeProfile"), "0x0EF0.json"))
    if not (defs and sup and node) then return nil end
    local m = {
        meta = { release = meta.release, version = meta.dataVersion, date = meta.date },
        defs = defs.definitions or defs,
        super = mra_props(sup.elProperties),
        classes = {},
    }
    local function add_class(d)
        local cls = tonumber(d.eoj or "")
        if not cls then return end
        local cn = d.className or {}
        local vr = d.validRelease or {}
        m.classes[cls] = { ja = cn.ja, en = cn.en, from = vr.from, to = vr.to,
                           props = mra_props(d.elProperties) }
    end
    add_class(node)
    local ddir = join(dir, "devices")
    if Dir.exists(ddir) then
        for name in Dir.open(ddir, ".json") do
            local d = read_json(join(ddir, name))
            if d then add_class(d) end
        end
    end
    return m, dir
end

local function mra_candidates(pref_dir)
    local c = {}
    if pref_dir and pref_dir ~= "" then c[#c + 1] = pref_dir end
    local ok, p = pcall(Dir.personal_config_path, "echonet_mra")
    if ok and p then c[#c + 1] = p end
    ok, p = pcall(Dir.personal_plugins_path)
    if ok and p then c[#c + 1] = join(p, "echonet_mra") end
    return c
end

local function load_mra(pref_dir)
    MRA, MRA_LOADED_FROM = nil, nil
    for _, dir in ipairs(mra_candidates(pref_dir)) do
        local ok, m, used = pcall(try_load_mra, dir)
        if ok and m then
            MRA, MRA_LOADED_FROM = m, used
            local n = 0
            for _ in pairs(m.classes) do n = n + 1 end
            MRA_STATUS = string.format("MRA %s (Release %s), %d classes: %s",
                tostring(m.meta.version), tostring(m.meta.release), n, used)
            return
        end
    end
    MRA_STATUS = "MRA not found (searched: " .. table.concat(mra_candidates(pref_dir), ", ") .. ")"
end

---------------------------------------------------------------------------
-- Preferences / language
---------------------------------------------------------------------------

local RELEASES = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
local LANG_JA, LANG_EN = 1, 2

el.prefs.language = Pref.enum("Language / 表示言語", LANG_JA,
    "Language for class names, property names and values", {
        { 1, "日本語 (Japanese)", LANG_JA },
        { 2, "English", LANG_EN },
    }, false)

local release_enum = { { 1, "Latest (最新)", 0 } }
for i = 1, #RELEASES do
    local r = RELEASES:sub(i, i)
    release_enum[#release_enum + 1] = { i + 1, "Release " .. r, i }
    if r == "R" then break end
end
el.prefs.release = Pref.enum("APPENDIX Release", 0,
    "Which Release of the APPENDIX to use when a property definition changed between Releases",
    release_enum, false)
el.prefs.mra_dir = Pref.string("MRA folder", "",
    "Folder of the unpacked Machine Readable Appendix (contains metaData.json). " ..
    "Empty: <personal configuration folder>/echonet_mra or <personal Lua plugins folder>/echonet_mra")
el.prefs.udp_port = Pref.uint("UDP port", 3610, "UDP port for ECHONET Lite")
el.prefs.heuristic = Pref.bool("Heuristic detection on other UDP ports", false,
    "Try to detect ECHONET Lite frames (EHD1=0x10, EHD2=0x81/0x82) on any UDP port")

local function ja() return el.prefs.language ~= LANG_EN end

-- Pick ja/en from a {ja=..., en=...} table
local function L(t)
    if t == nil then return nil end
    if type(t) == "string" then return t end
    if ja() then
        if t.ja and t.ja ~= "" then return t.ja end
        return t.en
    end
    if t.en and t.en ~= "" then return t.en end
    return t.ja
end

-- UI strings
local S = {
    all_instances = { ja = "全インスタンス", en = "all instances" },
    unknown_class = { ja = "不明なクラス", en = "Unknown class" },
    unknown_epc   = { ja = "不明", en = "Unknown" },
    user_epc      = { ja = "ユーザ定義領域", en = "User-defined (manufacturer specific)" },
    property      = { ja = "プロパティ", en = "Property" },
    set_property  = { ja = "Set プロパティ", en = "Set Property" },
    get_property  = { ja = "Get プロパティ", en = "Get Property" },
    value         = { ja = "値", en = "Value" },
    definition    = { ja = "定義", en = "Definition" },
    release_range = { ja = "Release %s〜%s", en = "Release %s - %s" },
    release_from  = { ja = "Release %s〜", en = "Release %s and later" },
    not_in_rel    = { ja = "（選択中の Release %s には存在しない定義）", en = " (not defined in selected Release %s)" },
    undefined     = { ja = "未定義値", en = "Undefined value" },
    overflow      = { ja = "オーバーフロー", en = "Overflow" },
    underflow     = { ja = "アンダーフロー", en = "Underflow" },
    out_of_range  = { ja = "範囲外", en = "out of range" },
    level         = { ja = "レベル %d", en = "Level %d" },
    coefficient   = { ja = "係数 EPC %s を乗じる", en = "multiply by coefficient EPC %s" },
    nprops        = { ja = "%d 個", en = "%d properties" },
    ninst         = { ja = "%d インスタンス", en = "%d instances" },
    nclass        = { ja = "%d クラス", en = "%d classes" },
    map_count     = { ja = "プロパティ数", en = "Number of properties" },
    inst_count    = { ja = "インスタンス数", en = "Number of instances" },
    class_count   = { ja = "クラス数", en = "Number of classes" },
    version_np    = { ja = "Ver.%d.%d（%s）", en = "Ver. %d.%d (%s)" },
    fmt1          = { ja = "規定電文形式のみ", en = "specified message format only" },
    fmt2          = { ja = "任意電文形式のみ", en = "arbitrary message format only" },
    fmt3          = { ja = "規定電文形式・任意電文形式", en = "specified and arbitrary message formats" },
    appendix_rel  = { ja = "APPENDIX Release %s rev.%d", en = "Appendix Release %s rev.%d" },
    arbitrary     = { ja = "任意電文形式", en = "Arbitrary message format" },
    truncated     = { ja = "電文が短すぎます", en = "Truncated ECHONET Lite frame" },
}
local function T(key) return L(S[key]) end

---------------------------------------------------------------------------
-- Static tables (header / ESV / class groups / class names outside the MRA)
---------------------------------------------------------------------------

local EHD1_NAMES = { [0x10] = "ECHONET Lite" }
local EHD2_NAMES = {
    [0x81] = "Format 1 (specified message format)",
    [0x82] = "Format 2 (arbitrary message format)",
}

local ESV_NAMES = {
    [0x60] = "SetI", [0x61] = "SetC", [0x62] = "Get", [0x63] = "INF_REQ", [0x6E] = "SetGet",
    [0x71] = "Set_Res", [0x72] = "Get_Res", [0x73] = "INF", [0x74] = "INFC", [0x7A] = "INFC_Res",
    [0x7E] = "SetGet_Res",
    [0x50] = "SetI_SNA", [0x51] = "SetC_SNA", [0x52] = "Get_SNA", [0x53] = "INF_SNA", [0x5E] = "SetGet_SNA",
}

local ESV_DESC = {
    [0x60] = { ja = "プロパティ値書き込み要求（応答不要）", en = "Property value write request (no response required)" },
    [0x61] = { ja = "プロパティ値書き込み要求（応答要）", en = "Property value write request (response required)" },
    [0x62] = { ja = "プロパティ値読み出し要求", en = "Property value read request" },
    [0x63] = { ja = "プロパティ値通知要求", en = "Property value notification request" },
    [0x6E] = { ja = "プロパティ値書き込み・読み出し要求", en = "Property value write & read request" },
    [0x71] = { ja = "プロパティ値書き込み応答", en = "Property value write response" },
    [0x72] = { ja = "プロパティ値読み出し応答", en = "Property value read response" },
    [0x73] = { ja = "プロパティ値通知", en = "Property value notification" },
    [0x74] = { ja = "プロパティ値通知（応答要）", en = "Property value notification (response required)" },
    [0x7A] = { ja = "プロパティ値通知応答", en = "Property value notification response" },
    [0x7E] = { ja = "プロパティ値書き込み・読み出し応答", en = "Property value write & read response" },
    [0x50] = { ja = "プロパティ値書き込み要求不可応答（応答不要）", en = "Property value write request (no response required) not possible" },
    [0x51] = { ja = "プロパティ値書き込み要求不可応答", en = "Property value write request not possible" },
    [0x52] = { ja = "プロパティ値読み出し不可応答", en = "Property value read not possible" },
    [0x53] = { ja = "プロパティ値通知不可応答", en = "Property value notification not possible" },
    [0x5E] = { ja = "プロパティ値書き込み・読み出し不可応答", en = "Property value write & read not possible" },
}

local SETGET_ESV = { [0x6E] = true, [0x7E] = true, [0x5E] = true }

local CLASS_GROUP_NAMES = {
    [0x00] = { ja = "センサ関連機器", en = "Sensor-related device" },
    [0x01] = { ja = "空調関連機器", en = "Air conditioner-related device" },
    [0x02] = { ja = "住宅・設備関連機器", en = "Housing/facility-related device" },
    [0x03] = { ja = "調理・家事関連機器", en = "Cooking/housework-related device" },
    [0x04] = { ja = "健康関連機器", en = "Health-related device" },
    [0x05] = { ja = "管理・操作関連機器", en = "Management/control-related device" },
    [0x06] = { ja = "AV関連機器", en = "Audiovisual-related device" },
    [0x0E] = { ja = "プロファイル", en = "Profile" },
    [0x0F] = { ja = "ユーザ定義", en = "User definition" },
}

-- Built-in class names (used when the MRA is not installed, and for classes the MRA does not cover)
local BUILTIN_CLASS_NAMES = {
    [0x0001] = { ja = "ガス漏れセンサ", en = "Gas leak sensor" },
    [0x0002] = { ja = "防犯センサ", en = "Crime prevention sensor" },
    [0x0003] = { ja = "非常ボタン", en = "Emergency button" },
    [0x0004] = { ja = "救急用センサ", en = "First-aid sensor" },
    [0x0005] = { ja = "地震センサ", en = "Earthquake sensor" },
    [0x0006] = { ja = "漏電センサ", en = "Electric leak sensor" },
    [0x0007] = { ja = "人体検知センサ", en = "Human detection sensor" },
    [0x0008] = { ja = "来客センサ", en = "Visitor sensor" },
    [0x0009] = { ja = "呼び出しセンサ", en = "Call sensor" },
    [0x000A] = { ja = "結露センサ", en = "Condensation sensor" },
    [0x000B] = { ja = "空気汚染センサ", en = "Air pollution sensor" },
    [0x000C] = { ja = "酸素センサ", en = "Oxygen sensor" },
    [0x000D] = { ja = "照度センサ", en = "Illuminance sensor" },
    [0x000E] = { ja = "音センサ", en = "Sound sensor" },
    [0x000F] = { ja = "投函センサ", en = "Mailing sensor" },
    [0x0010] = { ja = "重荷センサ", en = "Weight sensor" },
    [0x0011] = { ja = "温度センサ", en = "Temperature sensor" },
    [0x0012] = { ja = "湿度センサ", en = "Humidity sensor" },
    [0x0013] = { ja = "雨センサ", en = "Rain sensor" },
    [0x0014] = { ja = "水位センサ", en = "Water level sensor" },
    [0x0015] = { ja = "風呂水位センサ", en = "Bath water level sensor" },
    [0x0016] = { ja = "風呂沸き上がりセンサ", en = "Bath heating status sensor" },
    [0x0017] = { ja = "水漏れセンサ", en = "Water leak sensor" },
    [0x0018] = { ja = "水あふれセンサ", en = "Water overflow sensor" },
    [0x0019] = { ja = "火災センサ", en = "Fire sensor" },
    [0x001A] = { ja = "タバコ煙センサ", en = "Cigarette smoke sensor" },
    [0x001B] = { ja = "CO2センサ", en = "CO2 sensor" },
    [0x001C] = { ja = "ガスセンサ", en = "Gas sensor" },
    [0x001D] = { ja = "VOCセンサ", en = "VOC sensor" },
    [0x001E] = { ja = "差圧センサ", en = "Differential pressure sensor" },
    [0x001F] = { ja = "風速センサ", en = "Air speed sensor" },
    [0x0020] = { ja = "臭いセンサ", en = "Odor sensor" },
    [0x0021] = { ja = "炎センサ", en = "Flame sensor" },
    [0x0022] = { ja = "電力量センサ", en = "Electric energy sensor" },
    [0x0023] = { ja = "電流量センサ", en = "Current value sensor" },
    [0x0025] = { ja = "水流量センサ", en = "Water flow rate sensor" },
    [0x0026] = { ja = "微動センサ", en = "Micromotion sensor" },
    [0x0027] = { ja = "通過センサ", en = "Passage sensor" },
    [0x0028] = { ja = "在床センサ", en = "Bed presence sensor" },
    [0x0029] = { ja = "開閉センサ", en = "Open/close sensor" },
    [0x002A] = { ja = "活動量センサ", en = "Activity amount sensor" },
    [0x002B] = { ja = "人体位置センサ", en = "Human body location sensor" },
    [0x002C] = { ja = "雪センサ", en = "Snow sensor" },
    [0x002D] = { ja = "気圧センサ", en = "Air pressure sensor" },
    [0x0130] = { ja = "家庭用エアコン", en = "Home air conditioner" },
    [0x0131] = { ja = "", en = "Cold blaster" },
    [0x0132] = { ja = "扇風機", en = "Electric fan" },
    [0x0133] = { ja = "換気扇", en = "Ventilation fan" },
    [0x0134] = { ja = "空調換気扇", en = "Air conditioner ventilation fan" },
    [0x0135] = { ja = "空気清浄器", en = "Air cleaner" },
    [0x0136] = { ja = "", en = "Cold blast fan" },
    [0x0137] = { ja = "", en = "Circulator" },
    [0x0138] = { ja = "", en = "Dehumidifier" },
    [0x0139] = { ja = "加湿器", en = "Humidifier" },
    [0x0156] = { ja = "業務用パッケージエアコン室内機（設備用除く）", en = "Package-type commercial air conditioner (indoor unit, except for facility use)" },
    [0x0157] = { ja = "業務用パッケージエアコン室外機（設備用除く）", en = "Package-type commercial air conditioner (outdoor unit, except for facility use)" },
    [0x0260] = { ja = "電動ブラインド・日よけ", en = "Electrically operated blind/shade" },
    [0x0261] = { ja = "", en = "Electrically operated shutter" },
    [0x0262] = { ja = "電動カーテン", en = "Electrically operated curtain" },
    [0x0263] = { ja = "電動雨戸・シャッター", en = "Electrically operated rain sliding door/shutter" },
    [0x0264] = { ja = "電動ゲート", en = "Electrically operated gate" },
    [0x0265] = { ja = "電動窓", en = "Electrically operated window" },
    [0x0266] = { ja = "", en = "Automatically operated entrance door/sliding door" },
    [0x0267] = { ja = "", en = "Garden sprinkler" },
    [0x0268] = { ja = "", en = "Fire sprinkler" },
    [0x0269] = { ja = "", en = "Fountain" },
    [0x026A] = { ja = "", en = "Instantaneous water heater" },
    [0x026B] = { ja = "電気温水器", en = "Electric water heater" },
    [0x026C] = { ja = "太陽熱温水器", en = "Solar water heater" },
    [0x026D] = { ja = "", en = "Circulation pump" },
    [0x026E] = { ja = "電気便座（温水洗浄便座、暖房便座など）", en = "Bidet-equipped toilet (with electrically warmed seat)" },
    [0x026F] = { ja = "電気錠", en = "Electric lock" },
    [0x0270] = { ja = "", en = "Gas line valve" },
    [0x0271] = { ja = "ホームサウナ", en = "Home sauna" },
    [0x0272] = { ja = "瞬間式給湯器", en = "Hot water generator" },
    [0x0273] = { ja = "浴室暖房乾燥機", en = "Bathroom dryer" },
    [0x0274] = { ja = "ホームエレベータ", en = "Home elevator" },
    [0x0275] = { ja = "", en = "Electrically operated room divider" },
    [0x0276] = { ja = "", en = "Horizontal transfer" },
    [0x0277] = { ja = "", en = "Electrically operated clothes-drying pole" },
    [0x0278] = { ja = "", en = "Septic tank" },
    [0x0279] = { ja = "住宅用太陽光発電", en = "Household solar power generation" },
    [0x027A] = { ja = "冷温水熱源機", en = "Cold or hot water heat source equipment" },
    [0x027B] = { ja = "床暖房", en = "Floor heater" },
    [0x027C] = { ja = "燃料電池", en = "Fuel cell" },
    [0x027D] = { ja = "蓄電池", en = "Storage battery" },
    [0x027E] = { ja = "電気自動車充放電器", en = "Electric vehicle charger/discharger" },
    [0x027F] = { ja = "", en = "Engine cogeneration" },
    [0x0280] = { ja = "電力量メータ", en = "Electric energy meter" },
    [0x0281] = { ja = "水流量メータ", en = "Water flow meter" },
    [0x0282] = { ja = "ガスメータ", en = "Gas meter" },
    [0x0283] = { ja = "LPガスメータ", en = "LP gas meter" },
    [0x0284] = { ja = "時計", en = "Clock" },
    [0x0285] = { ja = "自動ドア", en = "Automatic door" },
    [0x0286] = { ja = "業務用エレベータ", en = "Commercial elevator" },
    [0x0287] = { ja = "分電盤メータリング", en = "Power distribution board metering" },
    [0x0288] = { ja = "低圧スマート電力量メータ", en = "Low-voltage smart electric energy meter" },
    [0x0289] = { ja = "スマートガスメータ", en = "Smart gas meter" },
    [0x028A] = { ja = "高圧スマート電力量メータ", en = "High-voltage smart electric energy meter" },
    [0x028B] = { ja = "灯油メータ", en = "Kerosene meter" },
    [0x028C] = { ja = "スマート灯油メータ", en = "Smart kerosene meter" },
    [0x028D] = { ja = "スマート電力量サブメータ", en = "Smart electric energy sub-meter" },
    [0x0290] = { ja = "一般照明", en = "General lighting" },
    [0x0291] = { ja = "単機能照明", en = "Mono functional lighting" },
    [0x0299] = { ja = "", en = "Emergency lighting" },
    [0x029D] = { ja = "", en = "Equipment light" },
    [0x02A0] = { ja = "ブザー", en = "Buzzer" },
    [0x02A1] = { ja = "電気自動車充電器", en = "Electric vehicle charger" },
    [0x02A2] = { ja = "家庭用小型風力発電", en = "Household small wind turbine power generation" },
    [0x02A3] = { ja = "照明システム", en = "Lighting system" },
    [0x02A4] = { ja = "", en = "Extended lighting system" },
    [0x02A5] = { ja = "マルチ入力PCS", en = "Multiple input PCS" },
    [0x02A6] = { ja = "ハイブリッド給湯機", en = "Hybrid water heater" },
    [0x02A7] = { ja = "", en = "Frequency regulation" },
    [0x02A8] = { ja = "", en = "Smart electric energy meter for sharing" },
    [0x03B0] = { ja = "コーヒーメーカ", en = "Coffee machine" },
    [0x03B1] = { ja = "", en = "Coffee mill" },
    [0x03B2] = { ja = "電気ポット", en = "Electric hot water pot" },
    [0x03B3] = { ja = "", en = "Electric stove" },
    [0x03B4] = { ja = "トースター", en = "Toaster" },
    [0x03B5] = { ja = "", en = "Juicer/food mixer" },
    [0x03B6] = { ja = "", en = "Food processor" },
    [0x03B7] = { ja = "冷凍冷蔵庫", en = "Refrigerator" },
    [0x03B8] = { ja = "オーブンレンジ", en = "Combination microwave oven" },
    [0x03B9] = { ja = "クッキングヒータ", en = "Cooking heater" },
    [0x03BA] = { ja = "オーブン", en = "Oven" },
    [0x03BB] = { ja = "炊飯器", en = "Rice cooker" },
    [0x03BC] = { ja = "", en = "Electronic jar" },
    [0x03BD] = { ja = "食器洗い機", en = "Dish washer" },
    [0x03BE] = { ja = "食器乾燥機", en = "Dish dryer" },
    [0x03BF] = { ja = "", en = "Electric rice card cooker" },
    [0x03C0] = { ja = "", en = "Keep-warm machine" },
    [0x03C1] = { ja = "", en = "Rice mill" },
    [0x03C2] = { ja = "", en = "Automatic bread cooker" },
    [0x03C3] = { ja = "", en = "Slow cooker" },
    [0x03C4] = { ja = "", en = "Electric pickles cooker" },
    [0x03C5] = { ja = "洗濯機", en = "Washing machine" },
    [0x03C6] = { ja = "衣類乾燥機", en = "Clothes dryer" },
    [0x03C7] = { ja = "", en = "Electric iron" },
    [0x03C8] = { ja = "", en = "Trouser press" },
    [0x03C9] = { ja = "", en = "Futon dryer" },
    [0x03CA] = { ja = "", en = "Small article/shoes dryer" },
    [0x03CB] = { ja = "電気掃除機", en = "Electric vacuum cleaner" },
    [0x03CC] = { ja = "", en = "Disposer" },
    [0x03CD] = { ja = "", en = "Electric mosquito catcher" },
    [0x03CE] = { ja = "業務用ショーケース", en = "Commercial show case" },
    [0x03CF] = { ja = "", en = "Commercial refrigerator" },
    [0x03D0] = { ja = "", en = "Commercial hot case" },
    [0x03D1] = { ja = "", en = "Commercial fryer" },
    [0x03D2] = { ja = "", en = "Commercial microwave oven" },
    [0x03D3] = { ja = "洗濯乾燥機", en = "Washer and dryer" },
    [0x03D4] = { ja = "", en = "Commercial show case outdoor unit" },
    [0x0401] = { ja = "体重計", en = "Weighing machine" },
    [0x0402] = { ja = "体温計", en = "Clinical thermometer" },
    [0x0403] = { ja = "血圧計", en = "Blood pressure meter" },
    [0x0404] = { ja = "血糖値計", en = "Blood sugar meter" },
    [0x0405] = { ja = "体脂肪計", en = "Body fat meter" },
    [0x05FA] = { ja = "", en = "Parallel processing combination-type power control" },
    [0x05FB] = { ja = "", en = "DR controller" },
    [0x05FC] = { ja = "", en = "Secure communication shared key setup node" },
    [0x05FD] = { ja = "スイッチ（JEM-A/HA端子対応）", en = "Switch (supporting JEM-A/HA terminals)" },
    [0x05FE] = { ja = "携帯端末", en = "Portable terminal" },
    [0x05FF] = { ja = "コントローラ", en = "Controller" },
    [0x0601] = { ja = "ディスプレー", en = "Display" },
    [0x0602] = { ja = "テレビ", en = "Television" },
    [0x0603] = { ja = "オーディオ", en = "Audio" },
    [0x0604] = { ja = "ネットワークカメラ", en = "Network camera" },
    [0x0EF0] = { ja = "ノードプロファイル", en = "Node profile" },
}

local LOCATION_NAMES = {
    [1] = { ja = "居間・リビング", en = "Living room" }, [2] = { ja = "食堂・ダイニング", en = "Dining room" },
    [3] = { ja = "台所・キッチン", en = "Kitchen" }, [4] = { ja = "浴室・バス", en = "Bathroom" },
    [5] = { ja = "トイレ", en = "Lavatory" }, [6] = { ja = "洗面所・脱衣所", en = "Washroom/changing room" },
    [7] = { ja = "廊下", en = "Passageway" }, [8] = { ja = "部屋", en = "Room" },
    [9] = { ja = "階段", en = "Stairway" }, [10] = { ja = "玄関", en = "Front door" },
    [11] = { ja = "納戸", en = "Storeroom" }, [12] = { ja = "庭・外周", en = "Garden/perimeter" },
    [13] = { ja = "車庫", en = "Garage" }, [14] = { ja = "ベランダ・バルコニー", en = "Veranda/balcony" },
    [15] = { ja = "その他", en = "Others" },
}

-- Built-in names of the device object super class / node profile (used without the MRA)
local SUPER_NAMES = {
    [0x80] = { ja = "動作状態", en = "Operation status" },
    [0x81] = { ja = "設置場所", en = "Installation location" },
    [0x82] = { ja = "規格Version情報", en = "Standard version information" },
    [0x83] = { ja = "識別番号", en = "Identification number" },
    [0x84] = { ja = "瞬時消費電力計測値", en = "Measured instantaneous power consumption" },
    [0x85] = { ja = "積算消費電力量計測値", en = "Measured cumulative electric energy consumption" },
    [0x86] = { ja = "メーカ異常コード", en = "Manufacturer's fault code" },
    [0x87] = { ja = "電流制限設定", en = "Current limit setting" },
    [0x88] = { ja = "異常発生状態", en = "Fault status" },
    [0x89] = { ja = "異常内容", en = "Fault description" },
    [0x8A] = { ja = "メーカコード", en = "Manufacturer code" },
    [0x8B] = { ja = "事業場コード", en = "Business facility code" },
    [0x8C] = { ja = "商品コード", en = "Product code" },
    [0x8D] = { ja = "製造番号", en = "Production number" },
    [0x8E] = { ja = "製造年月日", en = "Production date" },
    [0x8F] = { ja = "節電動作設定", en = "Power-saving operation setting" },
    [0x93] = { ja = "遠隔操作設定", en = "Remote control setting" },
    [0x97] = { ja = "現在時刻設定", en = "Current time setting" },
    [0x98] = { ja = "現在年月日設定", en = "Current date setting" },
    [0x99] = { ja = "電力制限設定", en = "Power limit setting" },
    [0x9A] = { ja = "積算運転時間", en = "Cumulative operating time" },
    [0x9B] = { ja = "SetMプロパティマップ", en = "SetM property map" },
    [0x9C] = { ja = "GetMプロパティマップ", en = "GetM property map" },
    [0x9D] = { ja = "状変アナウンスプロパティマップ", en = "Status change announcement property map" },
    [0x9E] = { ja = "Setプロパティマップ", en = "Set property map" },
    [0x9F] = { ja = "Getプロパティマップ", en = "Get property map" },
}
local NODE_NAMES = {
    [0x82] = { ja = "Version情報", en = "Version information" },
    [0xBF] = { ja = "個体識別情報", en = "Unique identifier data" },
    [0xD3] = { ja = "自ノードインスタンス数", en = "Number of self-node instances" },
    [0xD4] = { ja = "自ノードクラス数", en = "Number of self-node classes" },
    [0xD5] = { ja = "インスタンスリスト通知", en = "Instance list notification" },
    [0xD6] = { ja = "自ノードインスタンスリストS", en = "Self-node instance list S" },
    [0xD7] = { ja = "自ノードクラスリストS", en = "Self-node class list S" },
}

local FALLBACK_EPC_NAMES = {
    -- Node profile
    [0x0EF0] = {
        [0x80] = "Operating status",
        [0x82] = "Version information",
        [0x83] = "Identification number",
        [0x89] = "Fault content",
        [0xBF] = "Unique identifier data",
        [0xD3] = "Number of self-node instances",
        [0xD4] = "Number of self-node classes",
        [0xD5] = "Instance list notification",
        [0xD6] = "Self-node instance list S",
        [0xD7] = "Self-node class list S",
    },
    -- Temperature sensor
    [0x0011] = { [0xE0] = "Measured temperature value" },
    -- Humidity sensor
    [0x0012] = { [0xE0] = "Measured value of relative humidity" },
    -- Illuminance sensor
    [0x000D] = { [0xE0] = "Measured illuminance value (lux)", [0xE1] = "Measured illuminance value (kilolux)" },
    -- CO2 sensor
    [0x001B] = { [0xE0] = "Measured CO2 concentration" },
    -- Human detection sensor
    [0x0007] = { [0xB0] = "Detection threshold level", [0xB1] = "Human detection status" },
    -- Home air conditioner
    [0x0130] = {
        [0x8F] = "Power-saving operation setting",
        [0xA0] = "Air flow rate setting",
        [0xA1] = "Automatic control of air flow direction setting",
        [0xA3] = "Automatic swing of air flow setting",
        [0xA4] = "Air flow direction (vertical) setting",
        [0xA5] = "Air flow direction (horizontal) setting",
        [0xB0] = "Operation mode setting",
        [0xB1] = "Automatic temperature control setting",
        [0xB2] = "Normal/high-speed/silent operation setting",
        [0xB3] = "Set temperature value",
        [0xB4] = "Set value of relative humidity in dehumidifying mode",
        [0xB5] = "Set temperature value in cooling mode",
        [0xB6] = "Set temperature value in heating mode",
        [0xB7] = "Set temperature value in dehumidifying mode",
        [0xB8] = "Rated power consumption",
        [0xB9] = "Measured value of current consumption",
        [0xBA] = "Measured value of room relative humidity",
        [0xBB] = "Measured value of room temperature",
        [0xBC] = "Set temperature value of user remote control",
        [0xBD] = "Measured cooled air temperature",
        [0xBE] = "Measured outdoor air temperature",
        [0xBF] = "Relative temperature setting",
        [0xC0] = "Ventilation function setting",
        [0xC1] = "Humidifier function setting",
        [0xC4] = "Ventilation air flow rate setting",
        [0xC7] = "Air purifier function setting",
        [0xCA] = "Air refresher function setting",
        [0xCC] = "Self-cleaning function setting",
        [0xCD] = "Special function setting",
        [0xCE] = "Operation status of components",
        [0xCF] = "Thermostat setting override function",
        [0xD0] = "Air purification mode setting",
        [0xD1] = "Buzzer",
        [0x90] = "ON timer-based reservation setting",
        [0x91] = "ON timer setting (time)",
        [0x92] = "ON timer setting (relative time)",
        [0x94] = "OFF timer-based reservation setting",
        [0x95] = "OFF timer setting (time)",
        [0x96] = "OFF timer setting (relative time)",
    },
    -- Electric water heater
    [0x026B] = {
        [0xB0] = "Automatic water heating setting",
        [0xB1] = "Automatic water temperature control setting",
        [0xB2] = "Water heater status",
        [0xB3] = "Water heating temperature setting",
        [0xC0] = "Daytime reheating permission setting",
        [0xC1] = "Measured temperature of supplied water",
        [0xC3] = "Hot water supply status",
        [0xD1] = "Temperature of supplied water setting",
        [0xD3] = "Bath water temperature setting",
        [0xE0] = "Alarm status",
        [0xE1] = "Measured amount of remaining hot water",
        [0xE2] = "Tank capacity",
        [0xE3] = "Automatic bath water heating mode setting",
        [0xEA] = "Bath operation status monitor",
    },
    -- Electric lock
    [0x026F] = {
        [0xE0] = "Lock setting 1",
        [0xE1] = "Lock setting 2",
        [0xE2] = "Lock status of door guard",
        [0xE3] = "Door open/close status",
        [0xE4] = "Occupant/non-occupant status",
        [0xE5] = "Alarm status",
        [0xE6] = "Auto lock mode setting",
    },
    -- Household solar power generation
    [0x0279] = {
        [0xA0] = "Output power control setting 1",
        [0xA1] = "Output power control setting 2",
        [0xD0] = "System-interconnected type",
        [0xE0] = "Measured instantaneous amount of electricity generated",
        [0xE1] = "Measured cumulative amount of electric energy generated",
        [0xE3] = "Measured cumulative amount of electric energy sold",
        [0xE8] = "Rated power generation output (system-interconnected)",
        [0xE9] = "Rated power generation output (independent)",
    },
    -- Fuel cell
    [0x027C] = {
        [0xC1] = "Measured temperature of water in water heater",
        [0xC2] = "Rated power generation output",
        [0xC4] = "Measured instantaneous power generation output",
        [0xC5] = "Measured cumulative power generation output",
        [0xCA] = "Power generation setting",
        [0xCB] = "Power generation status",
    },
    -- Storage battery
    [0x027D] = {
        [0xA0] = "AC effective capacity (charging)",
        [0xA1] = "AC effective capacity (discharging)",
        [0xA4] = "AC chargeable electric energy",
        [0xA5] = "AC dischargeable electric energy",
        [0xA8] = "AC measured cumulative charging electric energy",
        [0xA9] = "AC measured cumulative discharging electric energy",
        [0xAA] = "AC charge amount setting value",
        [0xAB] = "AC discharge amount setting value",
        [0xC1] = "Charging method",
        [0xC2] = "Discharging method",
        [0xC8] = "Minimum/maximum charging electric power",
        [0xC9] = "Minimum/maximum discharging electric power",
        [0xCF] = "Working operation status",
        [0xD0] = "Rated electric energy",
        [0xD1] = "Rated capacity",
        [0xD2] = "Rated voltage",
        [0xD3] = "Measured instantaneous charging/discharging electric power",
        [0xD4] = "Measured instantaneous charging/discharging current",
        [0xD5] = "Measured instantaneous charging/discharging voltage",
        [0xD6] = "Measured cumulative discharging electric energy",
        [0xD8] = "Measured cumulative charging electric energy",
        [0xDA] = "Operation mode setting",
        [0xDB] = "System-interconnected type",
        [0xE2] = "Remaining stored electricity 1",
        [0xE3] = "Remaining stored electricity 2",
        [0xE4] = "Remaining stored electricity 3",
        [0xE5] = "Battery state of health",
        [0xE6] = "Battery type",
        [0xE7] = "Charging amount setting 1",
        [0xE8] = "Discharging amount setting 1",
        [0xEB] = "Charging electric power setting",
        [0xEC] = "Discharging electric power setting",
    },
    -- EV charger/discharger
    [0x027E] = {
        [0xC0] = "Dischargeable capacity of vehicle mounted battery 1",
        [0xC2] = "Remaining dischargeable capacity of vehicle mounted battery 1",
        [0xC7] = "Vehicle connection and chargeable/dischargeable status",
        [0xCF] = "Remaining battery capacity 3",
        [0xD3] = "Measured instantaneous charging/discharging electric energy",
        [0xDA] = "Operation mode setting",
        [0xE2] = "Remaining stored electricity 1",
        [0xE4] = "Remaining battery capacity 3",
    },
    -- Low-voltage smart electric energy meter
    [0x0288] = {
        [0xD3] = "Coefficient",
        [0xD7] = "Number of effective digits for cumulative amounts of electric energy",
        [0xE0] = "Measured cumulative amount of electric energy (normal direction)",
        [0xE1] = "Unit for cumulative amounts of electric energy",
        [0xE2] = "Historical data of measured cumulative amounts of electric energy 1 (normal direction)",
        [0xE3] = "Measured cumulative amounts of electric energy (reverse direction)",
        [0xE4] = "Historical data of measured cumulative amounts of electric energy 1 (reverse direction)",
        [0xE5] = "Day for which the historical data of measured cumulative amounts of electric energy is to be retrieved 1",
        [0xE7] = "Measured instantaneous electric energy",
        [0xE8] = "Measured instantaneous currents",
        [0xEA] = "Cumulative amounts of electric energy measured at fixed time (normal direction)",
        [0xEB] = "Cumulative amounts of electric energy measured at fixed time (reverse direction)",
        [0xEC] = "Historical data of measured cumulative amounts of electric energy 2",
        [0xED] = "Day for which the historical data of measured cumulative amounts of electric energy is to be retrieved 2",
    },
    -- General lighting
    [0x0290] = {
        [0xB0] = "Illuminance level",
        [0xB1] = "Light color setting",
        [0xB2] = "Illuminance level step setting",
        [0xB3] = "Light color step setting",
        [0xB4] = "Maximum specifiable values",
        [0xB5] = "Maximum value of settable level for night lighting",
        [0xB6] = "Lighting mode setting",
        [0xB7] = "Illuminance level setting for main lighting",
        [0xB8] = "Illuminance level step setting for main lighting",
        [0xB9] = "Illuminance level setting for night lighting",
        [0xBA] = "Illuminance level step setting for night lighting",
        [0xBB] = "Light color setting for main lighting",
        [0xBF] = "Light color setting for night lighting",
        [0xC0] = "RGB setting for color lighting",
    },
    -- Mono functional lighting
    [0x0291] = { [0xB0] = "Illuminance level" },
    -- Refrigerator
    [0x03B7] = {
        [0xB0] = "Door open/close status",
        [0xB1] = "Door open warning",
        [0xD1] = "Measured refrigerator compartment temperature",
        [0xD2] = "Measured freezer compartment temperature",
        [0xE0] = "Refrigerator compartment temperature setting",
        [0xE2] = "Freezer compartment temperature setting",
    },
    -- Controller
    [0x05FF] = {
        [0xC0] = "Controller ID",
        [0xC1] = "Number of devices controlled",
        [0xC2] = "Index",
        [0xC3] = "Device ID",
        [0xC4] = "Device type",
        [0xC5] = "Name",
        [0xC6] = "Connection status",
        [0xC7] = "Business code of the controlled device",
        [0xC8] = "Product code of the controlled device",
        [0xC9] = "Manufacture date of the controlled device",
        [0xCA] = "Registered information renewal date of the controlled device",
        [0xCB] = "Registered information renewal version information of the controlled device",
        [0xCC] = "Place to install the controlled device",
        [0xCD] = "Fault status of the controlled device",
        [0xCE] = "Set property map for the controlled device",
        [0xCF] = "Get property map for the controlled device",
        [0xE0] = "Installation address",
    },
}

local AC_MODE_NAMES = {
    [0x40] = "Other", [0x41] = "Automatic", [0x42] = "Cooling", [0x43] = "Heating",
    [0x44] = "Dehumidification", [0x45] = "Air circulator",
}

local CUM_UNIT_NAMES = {
    [0x00] = "1 kWh", [0x01] = "0.1 kWh", [0x02] = "0.01 kWh", [0x03] = "0.001 kWh",
    [0x04] = "0.0001 kWh", [0x0A] = "10 kWh", [0x0B] = "100 kWh", [0x0C] = "1000 kWh",
    [0x0D] = "10000 kWh",
}

local UNIT_NAMES = {
    Celsius = "℃", minute = { ja = "分", en = "min" }, minutes = { ja = "分", en = "min" },
    second = { ja = "秒", en = "s" }, days = { ja = "日", en = "days" }, degree = "°",
    liter = "L", m3 = "m³", ["m3/h"] = "m³/h", lux = "lx", klux = "klx",
    digit = { ja = "桁", en = "digits" },
}

---------------------------------------------------------------------------
-- Fields
---------------------------------------------------------------------------

local f = el.fields
f.ehd1      = ProtoField.uint8 ("echonetlite.ehd1", "EHD1", base.HEX, EHD1_NAMES)
f.ehd2      = ProtoField.uint8 ("echonetlite.ehd2", "EHD2", base.HEX, EHD2_NAMES)
f.tid       = ProtoField.uint16("echonetlite.tid", "TID", base.DEC_HEX)
f.edata     = ProtoField.bytes ("echonetlite.edata", "EDATA")
f.seoj      = ProtoField.uint24("echonetlite.seoj", "SEOJ", base.HEX)
f.deoj      = ProtoField.uint24("echonetlite.deoj", "DEOJ", base.HEX)
f.eoj_group = ProtoField.uint8 ("echonetlite.eoj.group", "Class group code", base.HEX)
f.eoj_class = ProtoField.uint16("echonetlite.eoj.class", "Class code", base.HEX)
f.eoj_inst  = ProtoField.uint8 ("echonetlite.eoj.instance", "Instance code", base.HEX)
f.esv       = ProtoField.uint8 ("echonetlite.esv", "ESV", base.HEX, ESV_NAMES)
f.opc       = ProtoField.uint8 ("echonetlite.opc", "OPC", base.DEC)
f.opcset    = ProtoField.uint8 ("echonetlite.opcset", "OPCSet", base.DEC)
f.opcget    = ProtoField.uint8 ("echonetlite.opcget", "OPCGet", base.DEC)
f.prop      = ProtoField.none  ("echonetlite.property", "Property")
f.epc       = ProtoField.uint8 ("echonetlite.epc", "EPC", base.HEX)
f.epc_name  = ProtoField.string("echonetlite.epc.name", "Property name")
f.pdc       = ProtoField.uint8 ("echonetlite.pdc", "PDC", base.DEC)
f.edt       = ProtoField.bytes ("echonetlite.edt", "EDT")
f.value     = ProtoField.string("echonetlite.edt.value", "Value")
f.element   = ProtoField.string("echonetlite.edt.element", "Element")
f.defrel    = ProtoField.string("echonetlite.edt.release", "Definition release")
f.map_count = ProtoField.uint8 ("echonetlite.propmap.count", "Number of properties", base.DEC)
f.map_epc   = ProtoField.uint8 ("echonetlite.propmap.epc", "Property", base.HEX)
f.inst_count= ProtoField.uint8 ("echonetlite.instlist.count", "Number of instances", base.DEC)
f.inst_eoj  = ProtoField.uint24("echonetlite.instlist.eoj", "EOJ", base.HEX)
f.cls_count = ProtoField.uint8 ("echonetlite.classlist.count", "Number of classes", base.DEC)
f.cls_code  = ProtoField.uint16("echonetlite.classlist.class", "Class", base.HEX)
f.payload   = ProtoField.bytes ("echonetlite.payload", "Arbitrary message")

local ef_short   = ProtoExpert.new("echonetlite.short", "Truncated ECHONET Lite frame",
                                   expert.group.MALFORMED, expert.severity.ERROR)
local ef_pdc     = ProtoExpert.new("echonetlite.pdc.mismatch", "EDT does not match the property definition",
                                   expert.group.PROTOCOL, expert.severity.WARN)
local ef_unk_esv = ProtoExpert.new("echonetlite.esv.unknown", "Unknown ESV",
                                   expert.group.PROTOCOL, expert.severity.WARN)
local ef_trailing= ProtoExpert.new("echonetlite.trailing", "Trailing bytes after last property",
                                   expert.group.PROTOCOL, expert.severity.WARN)
local ef_sna     = ProtoExpert.new("echonetlite.sna", "Request not possible (SNA response)",
                                   expert.group.RESPONSE_CODE, expert.severity.NOTE)
el.experts = { ef_short, ef_pdc, ef_unk_esv, ef_trailing, ef_sna }

---------------------------------------------------------------------------
-- Name lookup
---------------------------------------------------------------------------

local function release_index(r)
    if r == nil or r == "latest" then return 99 end
    local i = RELEASES:find(r, 1, true)
    return i or 99
end

local function selected_release()
    local i = el.prefs.release
    if i == nil or i == 0 then return 99 end
    return i
end

local function class_name(cls)
    local c = MRA and MRA.classes[cls]
    if c then return L(c) end
    local x = BUILTIN_CLASS_NAMES[cls]
    if x then return L(x) end
    return T("unknown_class")
end

local function eoj_string(v)
    return string.format("%06X (%s #%d)", v, class_name(bit.rshift(v, 8)), bit.band(v, 0xFF))
end

-- Choose the property variant valid for the selected Release.
-- Returns variant, valid_in_selected_release
local function pick_variant(list)
    if not list then return nil end
    local sel = selected_release()
    for _, v in ipairs(list) do
        if release_index(v.from) <= sel and sel <= release_index(v.to) then return v, true end
    end
    -- not defined in the selected release: use the newest one
    local best
    for _, v in ipairs(list) do
        if not best or release_index(v.to) > release_index(best.to) then best = v end
    end
    return best, false
end

-- Returns property definition (variant), valid flag
local function lookup_prop(cls, epc)
    if not MRA then return nil, false end
    local c = MRA.classes[cls]
    if c and c.props[epc] then return pick_variant(c.props[epc]) end
    if cls ~= 0x0EF0 and MRA.super[epc] then return pick_variant(MRA.super[epc]) end
    if cls == 0x0EF0 and MRA.super[epc] then return pick_variant(MRA.super[epc]) end
    return nil, false
end

local function epc_name(cls, epc)
    local v = lookup_prop(cls, epc)
    if v then return L(v) end
    if cls == 0x0EF0 and NODE_NAMES[epc] then return L(NODE_NAMES[epc]) end
    local fb = FALLBACK_EPC_NAMES[cls]
    if fb and fb[epc] then return fb[epc] end
    if SUPER_NAMES[epc] then return L(SUPER_NAMES[epc]) end
    if epc >= 0xF0 then return T("user_epc") end
    return T("unknown_epc")
end

---------------------------------------------------------------------------
-- Generic EDT decoder driven by the MRA data definitions
---------------------------------------------------------------------------

local FMT_SIZE = { int8 = 1, uint8 = 1, int16 = 2, uint16 = 2, int32 = 4, uint32 = 4 }

local function resolve(def, depth)
    depth = depth or 0
    if type(def) ~= "table" then return {} end
    local ref = def["$ref"]
    if ref and depth < 10 then
        ref = ref:match("([^/]+)$") or ref
        local base = resolve(MRA and MRA.defs[ref], depth + 1)
        local m = {}
        for k, v in pairs(base) do m[k] = v end
        for k, v in pairs(def) do if k ~= "$ref" then m[k] = v end end
        return m
    end
    return def
end

local function num_format(d)
    if d.format then return d.format end
    local lo, hi = d.minimum or 0, d.maximum or 255
    local signed = lo < 0
    if signed then
        if lo >= -128 and hi <= 127 then return "int8" end
        if lo >= -32768 and hi <= 32767 then return "int16" end
        return "int32"
    end
    if hi <= 0xFF then return "uint8" end
    if hi <= 0xFFFF then return "uint16" end
    return "uint32"
end

local def_size
def_size = function(def, depth)
    depth = (depth or 0) + 1
    if depth > 20 then return nil end
    local d = resolve(def)
    if d.oneOf then
        for _, a in ipairs(d.oneOf) do
            local s = def_size(a, depth)
            if s then return s end
        end
        return nil
    end
    local t = d.type
    if t == "number" then return FMT_SIZE[num_format(d)] or 1
    elseif t == "state" or t == "numericValue" or t == "bitmap" then return d.size or 1
    elseif t == "level" then return 1
    elseif t == "date-time" then return d.size or 7
    elseif t == "date" then return d.size or 4
    elseif t == "time" then return d.size or 3
    elseif t == "raw" then
        if d.minSize and d.minSize == d.maxSize then return d.minSize end
        return nil
    elseif t == "object" then
        local s = 0
        for _, p in ipairs(d.properties or {}) do
            local e = def_size(p.element, depth)
            if not e then return nil end
            s = s + e
        end
        return s
    elseif t == "array" then
        local isz = d.itemSize or def_size(d.items, depth)
        if isz and d.minItems and d.minItems == d.maxItems then return isz * d.maxItems end
        return nil
    end
    return nil
end

local function to_signed(v, bytes)
    local lim = 2 ^ (bytes * 8 - 1)
    if v >= lim then return v - 2 ^ (bytes * 8) end
    return v
end

local function fmt_number(v)
    if v == math.floor(v) and math.abs(v) < 1e15 then return string.format("%d", v) end
    local s = string.format("%.4f", v):gsub("0+$", ""):gsub("%.$", "")
    return s
end

local function unit_text(u)
    if not u then return "" end
    local n = UNIT_NAMES[u]
    if n then return " " .. L(n) end
    return " " .. u
end

local function state_lookup(d, raw)
    for _, e in ipairs(d.enum or {}) do
        if tonumber(e.edt) == raw then return L(e.descriptions) end
    end
    return nil
end

local function hex_of(r)
    return tostring(r:bytes())
end

local decode_def

local function overflow_codes(fmt)
    if fmt == "uint8" then return 0xFF, 0xFE
    elseif fmt == "uint16" then return 0xFFFF, 0xFFFE
    elseif fmt == "uint32" then return 0xFFFFFFFF, 0xFFFFFFFE
    elseif fmt == "int8" then return 0x7F, 0x80
    elseif fmt == "int16" then return 0x7FFF, 0x8000
    elseif fmt == "int32" then return 0x7FFFFFFF, 0x80000000
    end
end

local suppress_coef = false
local last_coef = nil

local function decode_number(d, raw, size, fmt)
    local of, uf = overflow_codes(fmt)
    if d.overflowCode ~= false and raw == of then return T("overflow") end
    if d.underflowCode ~= false and raw == uf then return T("underflow") end
    local v = raw
    if fmt:sub(1, 1) == "i" then v = to_signed(raw, size) end
    local scaled = v
    if d.multiple then scaled = v * d.multiple end
    local s = fmt_number(scaled) .. unit_text(d.unit)
    if (d.minimum and v < d.minimum) or (d.maximum and v > d.maximum) then
        s = s .. " (" .. T("out_of_range") .. ")"
    end
    if d.coefficient and #d.coefficient > 0 then
        local note = " (" .. string.format(T("coefficient"), table.concat(d.coefficient, ", ")) .. ")"
        if suppress_coef then last_coef = note else s = s .. note end
    end
    return s
end

-- Decode a value that is not backed by bytes (bitmap fields)
local function decode_scalar(def, value)
    local d = resolve(def)
    if d.type == "state" then
        return state_lookup(d, value) or string.format("%s 0x%X", T("undefined"), value)
    elseif d.type == "level" then
        if d.base then return string.format(T("level"), value - tonumber(d.base) + 1) end
        return string.format(T("level"), value)
    elseif d.type == "numericValue" then
        for _, e in ipairs(d.enum or {}) do
            if tonumber(e.edt) == value then return fmt_number(e.numericValue) end
        end
    elseif d.type == "number" then
        local v = value
        if d.multiple then v = v * d.multiple end
        return fmt_number(v) .. unit_text(d.unit)
    end
    return string.format("0x%X", value)
end

local function choose_alternative(d, edt, off, avail)
    local size = def_size(d) or avail
    local raw
    if size >= 1 and size <= 4 and size <= avail then raw = edt:range(off, size):uint() end
    -- 1. a state whose enum matches the raw value (special codes such as "no data")
    for _, alt in ipairs(d.oneOf) do
        local a = resolve(alt)
        if a.type == "state" and raw and state_lookup(a, raw) then return a end
    end
    -- 2. a number within range
    for _, alt in ipairs(d.oneOf) do
        local a = resolve(alt)
        if a.type == "number" and raw then
            local fmt = num_format(a)
            local sz = FMT_SIZE[fmt] or 1
            local v = raw
            if fmt:sub(1, 1) == "i" then v = to_signed(raw, sz) end
            if (not a.minimum or v >= a.minimum) and (not a.maximum or v <= a.maximum) then return a end
        end
    end
    -- 3. anything that is not a state / number
    for _, alt in ipairs(d.oneOf) do
        local a = resolve(alt)
        if a.type ~= "state" and a.type ~= "number" then return a end
    end
    return resolve(d.oneOf[1])
end

-- Returns text, consumed bytes. May add subtree items.
decode_def = function(def, edt, off, avail, tree, depth)
    depth = (depth or 0) + 1
    local d = resolve(def)
    if depth > 12 or avail <= 0 then return "", 0 end
    if d.oneOf then
        return decode_def(choose_alternative(d, edt, off, avail), edt, off, avail, tree, depth)
    end
    local t = d.type

    if t == "number" then
        local fmt = num_format(d)
        local size = FMT_SIZE[fmt] or 1
        if avail < size then return hex_of(edt:range(off, avail)), avail end
        return decode_number(d, edt:range(off, size):uint(), size, fmt), size

    elseif t == "state" or t == "numericValue" then
        local size = math.min(d.size or 1, avail)
        if size > 4 then return hex_of(edt:range(off, size)), size end
        local raw = edt:range(off, size):uint()
        if t == "state" then
            local s = state_lookup(d, raw)
            if s then return string.format("%s (0x%0" .. (size * 2) .. "X)", s, raw), size end
            return string.format("%s 0x%0" .. (size * 2) .. "X", T("undefined"), raw), size
        end
        return decode_scalar(d, raw), size

    elseif t == "level" then
        local raw = edt:range(off, 1):uint()
        local s = decode_scalar(d, raw)
        if d.base then
            local lvl = raw - tonumber(d.base) + 1
            if lvl < 1 or (d.maximum and lvl > d.maximum) then
                s = string.format("%s 0x%02X", T("undefined"), raw)
            end
        end
        return s, 1

    elseif t == "bitmap" then
        local size = math.min(d.size or 1, avail)
        local parts = {}
        for _, b in ipairs(d.bitmaps or {}) do
            local idx = b.position and b.position.index or 0
            local mask = tonumber((b.position and b.position.bitMask or "0b11111111"):sub(3), 2) or 0xFF
            if idx < size then
                local byte = edt:range(off + idx, 1):uint()
                local shift = 0
                while shift < 8 and bit.band(mask, bit.lshift(1, shift)) == 0 do shift = shift + 1 end
                local v = bit.rshift(bit.band(byte, mask), shift)
                local txt = decode_scalar(b.value or {}, v)
                local name = L(b.descriptions) or "?"
                if tree then
                    tree:add(f.element, edt:range(off + idx, 1), name .. ": " .. txt)
                        :set_text(name .. ": " .. txt)
                end
                parts[#parts + 1] = name .. "=" .. txt
            end
        end
        return table.concat(parts, ", "), size

    elseif t == "date-time" or t == "date" or t == "time" then
        local size = math.min(def_size(d) or avail, avail)
        local b = function(i) return edt:range(off + i, 1):uint() end
        if t == "time" then
            if size >= 3 then return string.format("%02d:%02d:%02d", b(0), b(1), b(2)), size end
            if size == 2 then return string.format("%02d:%02d", b(0), b(1)), size end
        elseif size >= 4 then
            local y = edt:range(off, 2):uint()
            if t == "date" then return string.format("%04d-%02d-%02d", y, b(2), b(3)), size end
            if size >= 7 then
                return string.format("%04d-%02d-%02d %02d:%02d:%02d", y, b(2), b(3), b(4), b(5), b(6)), size
            elseif size == 6 then
                return string.format("%04d-%02d-%02d %02d:%02d", y, b(2), b(3), b(4), b(5)), size
            end
        end
        return hex_of(edt:range(off, size)), size

    elseif t == "object" then
        local pos, parts = 0, {}
        for _, p in ipairs(d.properties or {}) do
            if pos >= avail then break end
            local esz = def_size(p.element) or (avail - pos)
            esz = math.min(esz, avail - pos)
            local name = L(p.elementName) or "?"
            local sub
            if tree then sub = tree:add(f.element, edt:range(off + pos, esz), "") end
            local txt, used = decode_def(p.element, edt, off + pos, esz, sub, depth)
            if sub then sub:set_text(name .. ": " .. txt) end
            parts[#parts + 1] = name .. "=" .. txt
            pos = pos + math.max(used, esz)
        end
        return table.concat(parts, ", "), pos

    elseif t == "array" then
        local isz = d.itemSize or def_size(d.items) or 1
        local n = math.floor(avail / isz)
        if d.maxItems and n > d.maxItems then n = d.maxItems end
        local parts = {}
        local saved = suppress_coef
        suppress_coef, last_coef = true, nil
        for i = 0, n - 1 do
            local sub
            if tree then sub = tree:add(f.element, edt:range(off + i * isz, isz), "") end
            local txt = decode_def(d.items, edt, off + i * isz, isz, sub, depth)
            if sub then sub:set_text(string.format("[%d] %s", i, txt)) end
            if #parts < 8 then parts[#parts + 1] = txt elseif #parts == 8 then parts[#parts + 1] = "…" end
        end
        suppress_coef = saved
        local note = last_coef or ""
        if note ~= "" and tree then tree:append_text(note) end
        return string.format("[%s]%s", table.concat(parts, ", "), note), n * isz

    else -- raw / unknown
        local r = edt:range(off, avail)
        local s = hex_of(r)
        local str = r:string()
        if #str > 0 and str:match("^[%g ]+%z*$") then
            s = s .. ' "' .. str:gsub("%z", "") .. '"'
        end
        return s, avail
    end
end

---------------------------------------------------------------------------
-- Special decoders (property maps, instance lists, version information)
---------------------------------------------------------------------------

local function decode_propmap(tree, edt, cls)
    local n = edt:range(0, 1):uint()
    tree:add(f.map_count, edt:range(0, 1)):set_text(T("map_count") .. ": " .. n)
    local epcs = {}
    if n < 16 then
        for i = 1, math.min(n, edt:len() - 1) do
            local r = edt:range(i, 1)
            local e = r:uint()
            epcs[#epcs + 1] = e
            tree:add(f.map_epc, r):set_text(string.format("0x%02X: %s", e, epc_name(cls, e)))
        end
    elseif edt:len() >= 17 then
        -- 16-byte bitmap: byte i (0..15), bit b (0..7) => EPC (0x80 + b*0x10 + i)
        for b = 0, 7 do
            for i = 0, 15 do
                local byte = edt:range(1 + i, 1):uint()
                if bit.band(byte, bit.lshift(1, b)) ~= 0 then
                    local e = 0x80 + b * 0x10 + i
                    epcs[#epcs + 1] = e
                    tree:add(f.map_epc, edt:range(1 + i, 1), e):set_text(
                        string.format("0x%02X: %s", e, epc_name(cls, e)))
                end
            end
        end
    end
    local parts = {}
    for _, e in ipairs(epcs) do parts[#parts + 1] = string.format("%02X", e) end
    return string.format(T("nprops"), n) .. " [" .. table.concat(parts, " ") .. "]"
end

local function decode_instlist(tree, edt)
    local n = edt:range(0, 1):uint()
    tree:add(f.inst_count, edt:range(0, 1)):set_text(T("inst_count") .. ": " .. n)
    local parts = {}
    local i = 1
    while i + 2 < edt:len() and #parts < n do
        local r = edt:range(i, 3)
        local v = r:uint()
        tree:add(f.inst_eoj, r):set_text("EOJ: " .. eoj_string(v))
        parts[#parts + 1] = string.format("%06X", v)
        i = i + 3
    end
    return string.format(T("ninst"), n) .. " [" .. table.concat(parts, " ") .. "]"
end

local function decode_classlist(tree, edt)
    local n = edt:range(0, 1):uint()
    tree:add(f.cls_count, edt:range(0, 1)):set_text(T("class_count") .. ": " .. n)
    local parts = {}
    local i = 1
    while i + 1 < edt:len() and #parts < n do
        local r = edt:range(i, 2)
        local c = r:uint()
        tree:add(f.cls_code, r):set_text(string.format("Class: %04X (%s)", c, class_name(c)))
        parts[#parts + 1] = string.format("%04X", c)
        i = i + 2
    end
    return string.format(T("nclass"), n) .. " [" .. table.concat(parts, " ") .. "]"
end

-- Returns text or nil (nil = use the generic MRA decoder)
local function decode_special(tree, cls, epc, edt)
    local len = edt:len()
    if epc >= 0x9B and epc <= 0x9F then return decode_propmap(tree, edt, cls) end
    if cls == 0x0EF0 then
        if epc == 0xD5 or epc == 0xD6 then return decode_instlist(tree, edt) end
        if epc == 0xD7 then return decode_classlist(tree, edt) end
        if (epc == 0xD3 and len == 3) or (epc == 0xD4 and len == 2) then
            return string.format(epc == 0xD3 and T("ninst") or T("nclass"), edt:uint())
        end
        if epc == 0x82 and len == 4 then
            local fmt = edt:range(2, 1):uint()
            local names = { [1] = T("fmt1"), [2] = T("fmt2"), [3] = T("fmt3") }
            return string.format(T("version_np"), edt:range(0, 1):uint(), edt:range(1, 1):uint(),
                                 names[fmt] or string.format("0x%02X", fmt))
        end
    end
    if epc == 0x82 and len == 4 and cls ~= 0x0EF0 then
        local rel = edt:range(2, 1):uint()
        if rel >= 0x41 and rel <= 0x5A then
            return string.format(T("appendix_rel"), string.char(rel), edt:range(3, 1):uint())
        end
    end
    if epc == 0x81 and len == 1 then
        local v = edt:uint()
        if v ~= 0x00 and v ~= 0x01 and v ~= 0xFF and bit.band(v, 0x80) == 0 then
            local loc = LOCATION_NAMES[bit.rshift(v, 3)]
            if loc then return string.format("%s #%d (0x%02X)", L(loc), bit.band(v, 0x07), v) end
        end
    end
    return nil
end

-- Value decoding used when the MRA is not installed (built-in, common properties only)
local function signed(v, bits)
    local lim = 2 ^ (bits - 1)
    if v >= lim then return v - 2 ^ bits end
    return v
end

local function fallback_value(tree, cls, epc, edt)
    local len = edt:len()
    if len == 0 then return nil end
    local u = function() return edt:uint() end

    -- Property maps
    if epc == 0x9B or epc == 0x9C or epc == 0x9D or epc == 0x9E or epc == 0x9F
       or (cls == 0x05FF and (epc == 0xCE or epc == 0xCF)) then
        return decode_propmap(tree, edt, cls)
    end

    -- Node profile
    if cls == 0x0EF0 then
        if (epc == 0xD5 or epc == 0xD6) then return decode_instlist(tree, edt) end
        if epc == 0xD7 then return decode_classlist(tree, edt) end
        if epc == 0xD3 and len == 3 then return string.format("%d instances", u()) end
        if epc == 0xD4 and len == 2 then return string.format("%d classes", u()) end
        if epc == 0x82 and len == 4 then
            local fmt = edt:range(2, 1):uint()
            local fmts = { [1] = "specified message format only", [2] = "arbitrary message format only",
                           [3] = "specified and arbitrary message formats" }
            return string.format("Ver. %d.%d (%s)", edt:range(0,1):uint(), edt:range(1,1):uint(),
                                 fmts[fmt] or string.format("format 0x%02X", fmt))
        end
        if epc == 0xBF and len == 2 then return string.format("0x%04X", u()) end
    end

    -- Super class (and node profile)
    if epc == 0x80 and len == 1 then
        local v = u()
        if v == 0x30 then return "ON (0x30)" elseif v == 0x31 then return "OFF (0x31)" end
    elseif epc == 0x81 and len == 1 then
        local v = u()
        if v == 0x00 then return "Installation location not specified" end
        if v == 0xFF then return "Installation location indefinite" end
        if v == 0x01 then return "Position information" end
        if bit.band(v, 0x80) ~= 0 then return string.format("Free definition (0x%02X)", v) end
        local loc = bit.rshift(v, 3)
        return string.format("%s #%d", L(LOCATION_NAMES[loc]) or "Reserved", bit.band(v, 0x07))
    elseif epc == 0x82 and len == 4 and cls ~= 0x0EF0 then
        local rel = edt:range(2, 1):uint()
        local revision = edt:range(3, 1):uint()
        if rel >= 0x20 and rel < 0x7F then
            return string.format("Appendix Release %s rev.%d", string.char(rel), revision)
        end
    elseif epc == 0x83 and len >= 1 then
        local h = edt:range(0, 1):uint()
        if h == 0xFE and len == 17 then
            return string.format("Manufacturer %s, ID %s", tostring(edt:range(1, 3):bytes()),
                                 tostring(edt:range(4, 13):bytes()))
        end
    elseif epc == 0x84 and len == 2 then
        return string.format("%d W", u())
    elseif epc == 0x85 and len == 4 then
        return string.format("%.3f kWh", u() / 1000)
    elseif epc == 0x88 and len == 1 then
        local v = u()
        if v == 0x41 then return "Fault occurred (0x41)" elseif v == 0x42 then return "No fault (0x42)" end
    elseif epc == 0x8A and len == 3 then
        return string.format("0x%06X", u())
    elseif epc == 0x8C or epc == 0x8D then
        local s = edt:string():gsub("%z", ""):gsub("%s+$", "")
        if s:match("^[%g ]*$") then return '"' .. s .. '"' end
    elseif epc == 0x8E and len == 4 then
        return string.format("%04d-%02d-%02d", edt:range(0, 2):uint(), edt:range(2, 1):uint(),
                             edt:range(3, 1):uint())
    elseif epc == 0x8F and len == 1 then
        local v = u()
        if v == 0x41 then return "Power-saving" elseif v == 0x42 then return "Normal" end
    elseif epc == 0x93 and len == 1 then
        local v = u()
        local t = { [0x41] = "Not through a public network", [0x42] = "Through a public network",
                    [0x61] = "Through a public network, normal", [0x62] = "Through a public network, abnormal" }
        if t[v] then return t[v] end
    elseif epc == 0x97 and len == 2 then
        return string.format("%02d:%02d", edt:range(0, 1):uint(), edt:range(1, 1):uint())
    elseif epc == 0x98 and len == 4 then
        return string.format("%04d-%02d-%02d", edt:range(0, 2):uint(), edt:range(2, 1):uint(),
                             edt:range(3, 1):uint())
    elseif epc == 0x9A and len == 5 then
        local units = { [0x41] = "s", [0x42] = "min", [0x43] = "h", [0x44] = "days" }
        return string.format("%d %s", edt:range(1, 4):uint(), units[edt:range(0, 1):uint()] or "?")
    end

    -- Class specific
    if cls == 0x0130 then
        if epc == 0xB0 and len == 1 then
            return AC_MODE_NAMES[u()] or string.format("0x%02X", u())
        elseif (epc == 0xB3 or epc == 0xB5 or epc == 0xB6 or epc == 0xB7) and len == 1 then
            local v = u()
            if v == 0xFD then return "Undefined" end
            return string.format("%d °C", v)
        elseif (epc == 0xBB or epc == 0xBD or epc == 0xBE) and len == 1 then
            local v = u()
            if v == 0x7E then return "Not measurable" end
            return string.format("%d °C", signed(v, 8))
        elseif (epc == 0xBA or epc == 0xB4) and len == 1 then
            return string.format("%d %%", u())
        elseif epc == 0xA0 and len == 1 then
            local v = u()
            if v == 0x41 then return "Automatic" end
            if v >= 0x31 and v <= 0x38 then return string.format("Level %d", v - 0x30) end
        elseif epc == 0xB8 and len == 8 then
            return string.format("Cooling %d W, Heating %d W, Dehumidifying %d W, Air circulation %d W",
                edt:range(0,2):uint(), edt:range(2,2):uint(), edt:range(4,2):uint(), edt:range(6,2):uint())
        end
    elseif cls == 0x0011 and epc == 0xE0 and len == 2 then
        local v = u()
        if v == 0x7FFE then return "Not measurable" end
        return string.format("%.1f °C", signed(v, 16) / 10)
    elseif cls == 0x0012 and epc == 0xE0 and len == 1 then
        return string.format("%d %%", u())
    elseif cls == 0x000D and epc == 0xE0 and len == 2 then
        return string.format("%d lx", u())
    elseif cls == 0x001B and epc == 0xE0 and len == 2 then
        return string.format("%d ppm", u())
    elseif cls == 0x0007 and epc == 0xB1 and len == 1 then
        local v = u()
        if v == 0x41 then return "Detected" elseif v == 0x42 then return "Not detected" end
    elseif cls == 0x0279 then
        if epc == 0xE0 and len == 2 then return string.format("%d W", u()) end
        if (epc == 0xE1 or epc == 0xE3) and len == 4 then return string.format("%.3f kWh", u() / 1000) end
    elseif cls == 0x027D or cls == 0x027E then
        if (epc == 0xE4 or epc == 0xCF) and len == 1 then return string.format("%d %%", u()) end
        if epc == 0xD3 and len == 4 then return string.format("%d W", signed(u(), 32)) end
        if epc == 0xDA and len == 1 then
            local t = { [0x40] = "Other", [0x41] = "Rapid charging", [0x42] = "Charging",
                        [0x43] = "Discharging", [0x44] = "Standby", [0x45] = "Test",
                        [0x46] = "Automatic", [0x48] = "Restart", [0x49] = "Effective capacity recalculation processing" }
            if t[u()] then return t[u()] end
        end
    elseif cls == 0x0288 then
        if epc == 0xD3 and len == 4 then return string.format("x%d", u()) end
        if epc == 0xD7 and len == 1 then return string.format("%d digits", u()) end
        if (epc == 0xE0 or epc == 0xE3) and len == 4 then return string.format("%d (see unit 0xE1)", u()) end
        if epc == 0xE1 and len == 1 then return CUM_UNIT_NAMES[u()] end
        if epc == 0xE7 and len == 4 then return string.format("%d W", signed(u(), 32)) end
        if epc == 0xE8 and len == 4 then
            local r = signed(edt:range(0, 2):uint(), 16)
            local t = signed(edt:range(2, 2):uint(), 16)
            local tstr = (t == 0x7FFE) and "N/A (single-phase 2-wire)" or string.format("%.1f A", t / 10)
            return string.format("R phase %.1f A, T phase %s", r / 10, tstr)
        end
        if (epc == 0xEA or epc == 0xEB) and len == 11 then
            return string.format("%04d-%02d-%02d %02d:%02d:%02d  %d",
                edt:range(0,2):uint(), edt:range(2,1):uint(), edt:range(3,1):uint(),
                edt:range(4,1):uint(), edt:range(5,1):uint(), edt:range(6,1):uint(),
                edt:range(7,4):uint())
        end
    elseif (cls == 0x0290 or cls == 0x0291) then
        if (epc == 0xB0 or epc == 0xB7 or epc == 0xB9) and len == 1 then return string.format("%d %%", u()) end
        if epc == 0xB6 and len == 1 then
            local t = { [0x41] = "Auto", [0x42] = "Normal lighting", [0x43] = "Night lighting", [0x45] = "Color lighting" }
            if t[u()] then return t[u()] end
        end
    elseif cls == 0x026F then
        if (epc == 0xE0 or epc == 0xE1 or epc == 0xE2) and len == 1 then
            local v = u()
            if v == 0x41 then return "Lock" elseif v == 0x42 then return "Unlock" end
        elseif epc == 0xE3 and len == 1 then
            local v = u()
            if v == 0x41 then return "Open" elseif v == 0x42 then return "Close" end
        end
    elseif cls == 0x026B then
        if epc == 0xE1 and len == 2 then return string.format("%d L", u()) end
        if epc == 0xE2 and len == 2 then return string.format("%d L", u()) end
        if (epc == 0xB3 or epc == 0xD1 or epc == 0xD3 or epc == 0xC1) and len == 1 then
            return string.format("%d °C", u())
        end
    end

    return nil
end

---------------------------------------------------------------------------
-- Property list
---------------------------------------------------------------------------

local function dissect_props(tvb, pinfo, tree, offset, count, cls, label_key)
    local epcs = {}
    for i = 1, count do
        if offset + 2 > tvb:len() then
            tree:add_proto_expert_info(ef_short, string.format(
                "Truncated: property %d of %d missing", i, count))
            break
        end
        local epc = tvb:range(offset, 1):uint()
        local pdc = tvb:range(offset + 1, 1):uint()
        local avail = math.min(pdc, tvb:len() - offset - 2)
        local variant, valid = lookup_prop(cls, epc)
        local name = variant and L(variant) or epc_name(cls, epc)
        local pt = tree:add(f.prop, tvb:range(offset, 2 + avail))
        local head = string.format("%s #%d: EPC 0x%02X %s, PDC %d", T(label_key), i, epc, name, pdc)
        pt:set_text(head)
        pt:add(f.epc, tvb:range(offset, 1)):append_text(" (" .. name .. ")")
        pt:add(f.epc_name, tvb:range(offset, 1), name):set_text(T("property") .. ": " .. name)
        if variant then
            local rel
            if variant.to == "latest" then
                rel = string.format(T("release_from"), variant.from)
            else
                rel = string.format(T("release_range"), variant.from, variant.to)
            end
            if not valid then
                local sel = selected_release()
                rel = rel .. string.format(T("not_in_rel"), RELEASES:sub(sel, sel))
            end
            pt:add(f.defrel, tvb:range(offset, 1), rel):set_text(T("definition") .. ": " .. rel)
        end
        pt:add(f.pdc, tvb:range(offset + 1, 1))
        epcs[#epcs + 1] = string.format("%02X", epc)
        if pdc > 0 then
            if avail < pdc then
                pt:add_proto_expert_info(ef_short, string.format(
                    "EDT truncated: PDC %d but only %d bytes", pdc, avail))
            end
            if avail > 0 then
                local edt = tvb:range(offset + 2, avail)
                local et = pt:add(f.edt, edt)
                local ok, val = pcall(decode_special, et, cls, epc, edt)
                if ok and val == nil and not variant then
                    ok, val = pcall(fallback_value, et, cls, epc, edt)
                end
                if ok and val == nil and variant then
                    ok, val = pcall(function()
                        local txt, used = decode_def(variant.data, edt, 0, avail, et, 0)
                        local need = def_size(variant.data)
                        if need and need ~= avail then
                            et:add_proto_expert_info(ef_pdc, string.format(
                                "PDC %d, but the definition expects %d bytes", avail, need))
                        end
                        return txt
                    end)
                end
                if ok and val and val ~= "" then
                    et:add(f.value, edt, val):set_text(T("value") .. ": " .. val)
                    pt:append_text(" = " .. val)
                elseif not ok then
                    et:add_proto_expert_info(ef_pdc, "Could not decode EDT: " .. tostring(val))
                end
            end
        end
        offset = offset + 2 + pdc
    end
    return offset, epcs
end

---------------------------------------------------------------------------
-- Main dissector
---------------------------------------------------------------------------

local function add_eoj(tree, field, tvbr, label)
    local v = tvbr:uint()
    local cls = bit.rshift(v, 8)
    local t = tree:add(field, tvbr)
    t:set_text(string.format("%s: %s", label, eoj_string(v)))
    local grp = bit.rshift(v, 16)
    t:add(f.eoj_group, tvbr:range(0, 1)):set_text(string.format("Class group code: 0x%02X (%s)",
        grp, L(CLASS_GROUP_NAMES[grp]) or T("unknown_class")))
    t:add(f.eoj_class, tvbr:range(0, 2)):set_text(string.format("Class code: 0x%04X (%s)",
        cls, class_name(cls)))
    local inst = bit.band(v, 0xFF)
    t:add(f.eoj_inst, tvbr:range(2, 1)):append_text(inst == 0 and (" (" .. T("all_instances") .. ")") or "")
    return v
end

local function looks_like_el(tvb)
    if tvb:len() < 4 then return false end
    local e1 = tvb:range(0, 1):uint()
    local e2 = tvb:range(1, 1):uint()
    if e1 ~= 0x10 then return false end
    if e2 == 0x82 then return true end
    if e2 ~= 0x81 or tvb:len() < 12 then return false end
    return ESV_NAMES[tvb:range(10, 1):uint()] ~= nil
end

local function dissect(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 4 then return 0 end

    pinfo.cols.protocol = "ECHONET Lite"
    local root = tree:add(el, tvb:range(0, len))
    local st = root:add(el, tvb:range(0, 0))
    st:set_text(MRA and MRA_STATUS or
        (MRA_STATUS .. " - " .. (ja() and "内蔵の簡易表で表示しています" or "using built-in tables")))
    st:set_generated()

    local ehd2 = tvb:range(1, 1):uint()
    local tid  = tvb:range(2, 2):uint()
    root:add(f.ehd1, tvb:range(0, 1))
    root:add(f.ehd2, tvb:range(1, 1))
    root:add(f.tid,  tvb:range(2, 2))

    if ehd2 == 0x82 then
        if len > 4 then root:add(f.payload, tvb:range(4)) end
        pinfo.cols.info = string.format("%s, TID=%d, %d bytes", T("arbitrary"), tid, len - 4)
        root:append_text(string.format(", Format 2, TID: %d", tid))
        return len
    end

    if len < 12 then
        root:add_proto_expert_info(ef_short, "Frame shorter than the 12-byte minimum")
        pinfo.cols.info = string.format("%s, TID=%d", T("truncated"), tid)
        return len
    end

    local edata = root:add(f.edata, tvb:range(4))
    edata:set_text("EDATA")
    local seoj = add_eoj(edata, f.seoj, tvb:range(4, 3), "SEOJ")
    local deoj = add_eoj(edata, f.deoj, tvb:range(7, 3), "DEOJ")
    local esv = tvb:range(10, 1):uint()
    local esv_item = edata:add(f.esv, tvb:range(10, 1))
    if ESV_DESC[esv] then
        esv_item:append_text(" - " .. L(ESV_DESC[esv]))
    else
        esv_item:add_proto_expert_info(ef_unk_esv)
    end
    if esv >= 0x50 and esv <= 0x5F then esv_item:add_proto_expert_info(ef_sna) end

    -- Properties belong to DEOJ for requests (0x6x) and INFC_Res (0x7A),
    -- and to SEOJ for the other responses / notifications.
    local owner = ((esv >= 0x60 and esv <= 0x6F) or esv == 0x7A) and deoj or seoj
    local cls = bit.rshift(owner, 8)

    local offset = 11
    local info_props
    if SETGET_ESV[esv] then
        local opcset = tvb:range(offset, 1):uint()
        edata:add(f.opcset, tvb:range(offset, 1))
        local epcs_set, epcs_get
        offset, epcs_set = dissect_props(tvb, pinfo, edata, offset + 1, opcset, cls, "set_property")
        if offset < len then
            local opcget = tvb:range(offset, 1):uint()
            edata:add(f.opcget, tvb:range(offset, 1))
            offset, epcs_get = dissect_props(tvb, pinfo, edata, offset + 1, opcget, cls, "get_property")
        else
            edata:add_proto_expert_info(ef_short, "OPCGet missing")
            epcs_get = {}
        end
        info_props = string.format("Set[%s] Get[%s]", table.concat(epcs_set, ","),
                                   table.concat(epcs_get, ","))
    else
        local opc = tvb:range(offset, 1):uint()
        edata:add(f.opc, tvb:range(offset, 1))
        local epcs
        offset, epcs = dissect_props(tvb, pinfo, edata, offset + 1, opc, cls, "property")
        info_props = "EPC[" .. table.concat(epcs, ",") .. "]"
    end

    if offset < len then
        edata:add_proto_expert_info(ef_trailing, string.format("%d trailing bytes", len - offset))
    end

    local esv_name = ESV_NAMES[esv] or string.format("ESV 0x%02X", esv)
    pinfo.cols.info = string.format("%s %06X -> %06X TID=%d %s",
        esv_name, seoj, deoj, tid, info_props)
    root:append_text(string.format(", %s, TID: %d, %s -> %s", esv_name, tid,
        class_name(bit.rshift(seoj, 8)), class_name(bit.rshift(deoj, 8))))
    return len
end

function el.dissector(tvb, pinfo, tree)
    return dissect(tvb, pinfo, tree)
end

local function heuristic(tvb, pinfo, tree)
    if not el.prefs.heuristic then return false end
    if not looks_like_el(tvb) then return false end
    dissect(tvb, pinfo, tree)
    pinfo.conversation = el
    return true
end

load_mra(el.prefs.mra_dir)
local loaded_mra_pref = el.prefs.mra_dir

local udp_table = DissectorTable.get("udp.port")
local current_port = el.prefs.udp_port
udp_table:add(current_port, el)
el:register_heuristic("udp", heuristic)

function el.prefs_changed()
    if loaded_mra_pref ~= el.prefs.mra_dir then
        loaded_mra_pref = el.prefs.mra_dir
        load_mra(el.prefs.mra_dir)
    end
    if current_port ~= el.prefs.udp_port then
        if current_port ~= 0 then udp_table:remove(current_port, el) end
        current_port = el.prefs.udp_port
        if current_port ~= 0 then udp_table:add(current_port, el) end
    end
end
