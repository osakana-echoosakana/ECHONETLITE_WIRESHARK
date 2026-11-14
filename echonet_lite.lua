--[[
  ECHONET Lite dissector for Wireshark (Lua)

  - UDP port 3610 (default, changeable in Preferences)
  - EHD1 / EHD2 / TID
  - SEOJ / DEOJ (class group / class / instance, with names)
  - ESV (with names), including the two OPC sections of SetGet / SetGet_Res / SetGet_SNA
  - OPC / EPC / PDC / EDT, with names for common EPCs and decoding of
    common values (operation status, property maps, instance lists, ...)

  Install: copy this file into Wireshark's personal Lua plugins folder
  (Help > About Wireshark > Folders > "Personal Lua Plugins") and restart.

  License: MIT
]]

local PLUGIN_VERSION = "1.0.0"

set_plugin_info({
    version     = PLUGIN_VERSION,
    description = "ECHONET Lite dissector",
    author      = "ECHONET Lite with Wireshark project",
    repository  = "https://github.com/osakana-echoosakana/ECHONETLITE_WIRESHARK",
})

local el = Proto("echonetlite", "ECHONET Lite")

---------------------------------------------------------------------------
-- Value tables
---------------------------------------------------------------------------

local EHD1_NAMES = {
    [0x10] = "ECHONET Lite",
}

local EHD2_NAMES = {
    [0x81] = "Format 1 (specified message format)",
    [0x82] = "Format 2 (arbitrary message format)",
}

local ESV_NAMES = {
    -- Requests
    [0x60] = "SetI",        -- Property value write request (no response required)
    [0x61] = "SetC",        -- Property value write request (response required)
    [0x62] = "Get",         -- Property value read request
    [0x63] = "INF_REQ",     -- Property value notification request
    [0x6E] = "SetGet",      -- Property value write & read request
    -- Responses / notifications
    [0x71] = "Set_Res",
    [0x72] = "Get_Res",
    [0x73] = "INF",
    [0x74] = "INFC",
    [0x7A] = "INFC_Res",
    [0x7E] = "SetGet_Res",
    -- Not-possible responses
    [0x50] = "SetI_SNA",
    [0x51] = "SetC_SNA",
    [0x52] = "Get_SNA",
    [0x53] = "INF_SNA",
    [0x5E] = "SetGet_SNA",
}

local ESV_DESC = {
    [0x60] = "Property value write request (no response required)",
    [0x61] = "Property value write request (response required)",
    [0x62] = "Property value read request",
    [0x63] = "Property value notification request",
    [0x6E] = "Property value write & read request",
    [0x71] = "Property value write response",
    [0x72] = "Property value read response",
    [0x73] = "Property value notification",
    [0x74] = "Property value notification (response required)",
    [0x7A] = "Property value notification response",
    [0x7E] = "Property value write & read response",
    [0x50] = "Property value write request (no response) not possible",
    [0x51] = "Property value write request not possible",
    [0x52] = "Property value read not possible",
    [0x53] = "Property value notification not possible",
    [0x5E] = "Property value write & read not possible",
}

local SETGET_ESV = { [0x6E] = true, [0x7E] = true, [0x5E] = true }

local CLASS_GROUP_NAMES = {
    [0x00] = "Sensor-related device",
    [0x01] = "Air conditioner-related device",
    [0x02] = "Housing/facility-related device",
    [0x03] = "Cooking/housework-related device",
    [0x04] = "Health-related device",
    [0x05] = "Management/control-related device",
    [0x06] = "Audiovisual-related device",
    [0x0E] = "Profile",
    [0x0F] = "User definition",
}

-- key = (class group << 8) | class
local CLASS_NAMES = {
    -- 0x00 Sensors
    [0x0001] = "Gas leak sensor",
    [0x0002] = "Crime prevention sensor",
    [0x0003] = "Emergency button",
    [0x0004] = "First-aid sensor",
    [0x0005] = "Earthquake sensor",
    [0x0006] = "Electric leak sensor",
    [0x0007] = "Human detection sensor",
    [0x0008] = "Visitor sensor",
    [0x0009] = "Call sensor",
    [0x000A] = "Condensation sensor",
    [0x000B] = "Air pollution sensor",
    [0x000C] = "Oxygen sensor",
    [0x000D] = "Illuminance sensor",
    [0x000E] = "Sound sensor",
    [0x000F] = "Mailing sensor",
    [0x0010] = "Weight sensor",
    [0x0011] = "Temperature sensor",
    [0x0012] = "Humidity sensor",
    [0x0013] = "Rain sensor",
    [0x0014] = "Water level sensor",
    [0x0015] = "Bath water level sensor",
    [0x0016] = "Bath heating status sensor",
    [0x0017] = "Water leak sensor",
    [0x0018] = "Water overflow sensor",
    [0x0019] = "Fire sensor",
    [0x001A] = "Cigarette smoke sensor",
    [0x001B] = "CO2 sensor",
    [0x001C] = "Gas sensor",
    [0x001D] = "VOC sensor",
    [0x001E] = "Differential pressure sensor",
    [0x001F] = "Air speed sensor",
    [0x0020] = "Odor sensor",
    [0x0021] = "Flame sensor",
    [0x0022] = "Electric energy sensor",
    [0x0023] = "Current value sensor",
    [0x0025] = "Water flow rate sensor",
    [0x0026] = "Micromotion sensor",
    [0x0027] = "Passage sensor",
    [0x0028] = "Bed presence sensor",
    [0x0029] = "Open/close sensor",
    [0x002A] = "Activity amount sensor",
    [0x002B] = "Human body location sensor",
    [0x002C] = "Snow sensor",
    [0x002D] = "Air pressure sensor",
    -- 0x01 Air conditioners
    [0x0130] = "Home air conditioner",
    [0x0131] = "Cold blaster",
    [0x0132] = "Electric fan",
    [0x0133] = "Ventilation fan",
    [0x0134] = "Air conditioner ventilation fan",
    [0x0135] = "Air cleaner",
    [0x0136] = "Cold blast fan",
    [0x0137] = "Circulator",
    [0x0138] = "Dehumidifier",
    [0x0139] = "Humidifier",
    [0x0156] = "Package-type commercial air conditioner (indoor unit, except for facility use)",
    [0x0157] = "Package-type commercial air conditioner (outdoor unit, except for facility use)",
    -- 0x02 Housing / facilities
    [0x0260] = "Electrically operated blind/shade",
    [0x0261] = "Electrically operated shutter",
    [0x0262] = "Electrically operated curtain",
    [0x0263] = "Electrically operated rain sliding door/shutter",
    [0x0264] = "Electrically operated gate",
    [0x0265] = "Electrically operated window",
    [0x0266] = "Automatically operated entrance door/sliding door",
    [0x0267] = "Garden sprinkler",
    [0x0268] = "Fire sprinkler",
    [0x0269] = "Fountain",
    [0x026A] = "Instantaneous water heater",
    [0x026B] = "Electric water heater",
    [0x026C] = "Solar water heater",
    [0x026D] = "Circulation pump",
    [0x026E] = "Bidet-equipped toilet (with electrically warmed seat)",
    [0x026F] = "Electric lock",
    [0x0270] = "Gas line valve",
    [0x0271] = "Home sauna",
    [0x0272] = "Hot water generator",
    [0x0273] = "Bathroom dryer",
    [0x0274] = "Home elevator",
    [0x0275] = "Electrically operated room divider",
    [0x0276] = "Horizontal transfer",
    [0x0277] = "Electrically operated clothes-drying pole",
    [0x0278] = "Septic tank",
    [0x0279] = "Household solar power generation",
    [0x027A] = "Cold or hot water heat source equipment",
    [0x027B] = "Floor heater",
    [0x027C] = "Fuel cell",
    [0x027D] = "Storage battery",
    [0x027E] = "Electric vehicle charger/discharger",
    [0x027F] = "Engine cogeneration",
    [0x0280] = "Electric energy meter",
    [0x0281] = "Water flow meter",
    [0x0282] = "Gas meter",
    [0x0283] = "LP gas meter",
    [0x0284] = "Clock",
    [0x0285] = "Automatic door",
    [0x0286] = "Commercial elevator",
    [0x0287] = "Power distribution board metering",
    [0x0288] = "Low-voltage smart electric energy meter",
    [0x0289] = "Smart gas meter",
    [0x028A] = "High-voltage smart electric energy meter",
    [0x028B] = "Kerosene meter",
    [0x028C] = "Smart kerosene meter",
    [0x028D] = "Smart electric energy sub-meter",
    [0x0290] = "General lighting",
    [0x0291] = "Mono functional lighting",
    [0x0299] = "Emergency lighting",
    [0x029D] = "Equipment light",
    [0x02A0] = "Buzzer",
    [0x02A1] = "Electric vehicle charger",
    [0x02A2] = "Household small wind turbine power generation",
    [0x02A3] = "Lighting system",
    [0x02A4] = "Extended lighting system",
    [0x02A5] = "Multiple input PCS",
    [0x02A6] = "Hybrid water heater",
    [0x02A7] = "Frequency regulation",
    [0x02A8] = "Smart electric energy meter for sharing",
    -- 0x03 Cooking / housework
    [0x03B0] = "Coffee machine",
    [0x03B1] = "Coffee mill",
    [0x03B2] = "Electric hot water pot",
    [0x03B3] = "Electric stove",
    [0x03B4] = "Toaster",
    [0x03B5] = "Juicer/food mixer",
    [0x03B6] = "Food processor",
    [0x03B7] = "Refrigerator",
    [0x03B8] = "Combination microwave oven",
    [0x03B9] = "Cooking heater",
    [0x03BA] = "Oven",
    [0x03BB] = "Rice cooker",
    [0x03BC] = "Electronic jar",
    [0x03BD] = "Dish washer",
    [0x03BE] = "Dish dryer",
    [0x03BF] = "Electric rice card cooker",
    [0x03C0] = "Keep-warm machine",
    [0x03C1] = "Rice mill",
    [0x03C2] = "Automatic bread cooker",
    [0x03C3] = "Slow cooker",
    [0x03C4] = "Electric pickles cooker",
    [0x03C5] = "Washing machine",
    [0x03C6] = "Clothes dryer",
    [0x03C7] = "Electric iron",
    [0x03C8] = "Trouser press",
    [0x03C9] = "Futon dryer",
    [0x03CA] = "Small article/shoes dryer",
    [0x03CB] = "Electric vacuum cleaner",
    [0x03CC] = "Disposer",
    [0x03CD] = "Electric mosquito catcher",
    [0x03CE] = "Commercial show case",
    [0x03CF] = "Commercial refrigerator",
    [0x03D0] = "Commercial hot case",
    [0x03D1] = "Commercial fryer",
    [0x03D2] = "Commercial microwave oven",
    [0x03D3] = "Washer and dryer",
    [0x03D4] = "Commercial show case outdoor unit",
    -- 0x04 Health
    [0x0401] = "Weighing machine",
    [0x0402] = "Clinical thermometer",
    [0x0403] = "Blood pressure meter",
    [0x0404] = "Blood sugar meter",
    [0x0405] = "Body fat meter",
    -- 0x05 Management / control
    [0x05FA] = "Parallel processing combination-type power control",
    [0x05FB] = "DR controller",
    [0x05FC] = "Secure communication shared key setup node",
    [0x05FD] = "Switch (supporting JEM-A/HA terminals)",
    [0x05FE] = "Portable terminal",
    [0x05FF] = "Controller",
    -- 0x06 AV
    [0x0601] = "Display",
    [0x0602] = "Television",
    [0x0603] = "Audio",
    [0x0604] = "Network camera",
    -- 0x0E Profile
    [0x0EF0] = "Node profile",
}

-- Device object super class EPCs (0x80 - 0x9F)
local SUPER_EPC_NAMES = {
    [0x80] = "Operation status",
    [0x81] = "Installation location",
    [0x82] = "Standard version information",
    [0x83] = "Identification number",
    [0x84] = "Measured instantaneous power consumption",
    [0x85] = "Measured cumulative electric energy consumption",
    [0x86] = "Manufacturer's fault code",
    [0x87] = "Current limit setting",
    [0x88] = "Fault status",
    [0x89] = "Fault description",
    [0x8A] = "Manufacturer code",
    [0x8B] = "Business facility code",
    [0x8C] = "Product code",
    [0x8D] = "Production number",
    [0x8E] = "Production date",
    [0x8F] = "Power-saving operation setting",
    [0x93] = "Remote control setting",
    [0x97] = "Current time setting",
    [0x98] = "Current date setting",
    [0x99] = "Power limit setting",
    [0x9A] = "Cumulative operating time",
    [0x9B] = "SetM property map",
    [0x9C] = "GetM property map",
    [0x9D] = "Status change announcement property map",
    [0x9E] = "Set property map",
    [0x9F] = "Get property map",
}

-- Class specific EPC names, key = class code (group<<8|class)
local CLASS_EPC_NAMES = {
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

local LOCATION_NAMES = {
    [1] = "Living room", [2] = "Dining room", [3] = "Kitchen", [4] = "Bathroom",
    [5] = "Lavatory", [6] = "Washroom/changing room", [7] = "Passageway", [8] = "Room",
    [9] = "Stairway", [10] = "Front door", [11] = "Storeroom", [12] = "Garden/perimeter",
    [13] = "Garage", [14] = "Veranda/balcony", [15] = "Others",
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
f.eoj_group = ProtoField.uint8 ("echonetlite.eoj.group", "Class group code", base.HEX, CLASS_GROUP_NAMES)
f.eoj_class = ProtoField.uint16("echonetlite.eoj.class", "Class code", base.HEX, CLASS_NAMES)
f.eoj_inst  = ProtoField.uint8 ("echonetlite.eoj.instance", "Instance code", base.HEX)
f.esv       = ProtoField.uint8 ("echonetlite.esv", "ESV", base.HEX, ESV_NAMES)
f.opc       = ProtoField.uint8 ("echonetlite.opc", "OPC", base.DEC)
f.opcset    = ProtoField.uint8 ("echonetlite.opcset", "OPCSet", base.DEC)
f.opcget    = ProtoField.uint8 ("echonetlite.opcget", "OPCGet", base.DEC)
f.prop      = ProtoField.none  ("echonetlite.property", "Property")
f.epc       = ProtoField.uint8 ("echonetlite.epc", "EPC", base.HEX)
f.pdc       = ProtoField.uint8 ("echonetlite.pdc", "PDC", base.DEC)
f.edt       = ProtoField.bytes ("echonetlite.edt", "EDT")
f.value     = ProtoField.string("echonetlite.edt.value", "Value")
f.map_count = ProtoField.uint8 ("echonetlite.propmap.count", "Number of properties", base.DEC)
f.map_epc   = ProtoField.uint8 ("echonetlite.propmap.epc", "Property", base.HEX)
f.inst_count= ProtoField.uint8 ("echonetlite.instlist.count", "Number of instances", base.DEC)
f.inst_eoj  = ProtoField.uint24("echonetlite.instlist.eoj", "EOJ", base.HEX)
f.cls_count = ProtoField.uint8 ("echonetlite.classlist.count", "Number of classes", base.DEC)
f.cls_code  = ProtoField.uint16("echonetlite.classlist.class", "Class", base.HEX, CLASS_NAMES)
f.payload   = ProtoField.bytes ("echonetlite.payload", "Arbitrary message")

local ef_short   = ProtoExpert.new("echonetlite.short", "Truncated ECHONET Lite frame",
                                   expert.group.MALFORMED, expert.severity.ERROR)
local ef_pdc     = ProtoExpert.new("echonetlite.pdc.mismatch", "Unexpected EDT length for this EPC",
                                   expert.group.PROTOCOL, expert.severity.WARN)
local ef_unk_esv = ProtoExpert.new("echonetlite.esv.unknown", "Unknown ESV",
                                   expert.group.PROTOCOL, expert.severity.WARN)
local ef_trailing= ProtoExpert.new("echonetlite.trailing", "Trailing bytes after last property",
                                   expert.group.PROTOCOL, expert.severity.WARN)
local ef_sna     = ProtoExpert.new("echonetlite.sna", "Request not possible (SNA response)",
                                   expert.group.RESPONSE_CODE, expert.severity.NOTE)
el.experts = { ef_short, ef_pdc, ef_unk_esv, ef_trailing, ef_sna }

el.prefs.udp_port = Pref.uint("UDP port", 3610, "UDP port for ECHONET Lite")
el.prefs.heuristic = Pref.bool("Heuristic detection on other UDP ports", false,
    "Try to detect ECHONET Lite frames (EHD1=0x10, EHD2=0x81/0x82) on any UDP port")

---------------------------------------------------------------------------
-- Helpers
---------------------------------------------------------------------------

local function class_name(cls)
    return CLASS_NAMES[cls] or "Unknown class"
end

local function eoj_string(v)
    local cls = bit.rshift(v, 8)
    return string.format("%06X (%s #%d)", v, class_name(cls), bit.band(v, 0xFF))
end

local function epc_name(cls, epc)
    local t = CLASS_EPC_NAMES[cls]
    if t and t[epc] then return t[epc] end
    if cls ~= 0x0EF0 and SUPER_EPC_NAMES[epc] then return SUPER_EPC_NAMES[epc] end
    -- Node profile shares most super class properties
    if cls == 0x0EF0 and SUPER_EPC_NAMES[epc] then return SUPER_EPC_NAMES[epc] end
    if epc >= 0xF0 then return "User-defined (manufacturer specific)" end
    return "Unknown"
end

local function add_eoj(tree, field, tvbr, label)
    local v = tvbr:uint()
    local t = tree:add(field, tvbr)
    t:set_text(string.format("%s: %s", label, eoj_string(v)))
    t:add(f.eoj_group, tvbr:range(0, 1))
    t:add(f.eoj_class, tvbr:range(0, 2))
    t:add(f.eoj_inst,  tvbr:range(2, 1)):append_text(
        bit.band(v, 0xFF) == 0 and " (all instances)" or "")
    return v
end

local function signed(v, bits)
    local lim = 2 ^ (bits - 1)
    if v >= lim then return v - 2 ^ bits end
    return v
end

-- Decode a property map (EPC 0x9B-0x9F, 0xCE/0xCF of controller)
local function decode_propmap(tree, edt, cls)
    local n = edt:range(0, 1):uint()
    tree:add(f.map_count, edt:range(0, 1))
    local epcs = {}
    if n < 16 then
        for i = 1, math.min(n, edt:len() - 1) do
            local r = edt:range(i, 1)
            local e = r:uint()
            epcs[#epcs + 1] = e
            tree:add(f.map_epc, r):append_text(" (" .. epc_name(cls, e) .. ")")
        end
    elseif edt:len() >= 17 then
        -- 16-byte bitmap: byte i (0..15), bit b (0..7) => EPC (0x80 + b*0x10 + i)
        for b = 0, 7 do
            for i = 0, 15 do
                local byte = edt:range(1 + i, 1):uint()
                if bit.band(byte, bit.lshift(1, b)) ~= 0 then
                    local e = 0x80 + b * 0x10 + i
                    epcs[#epcs + 1] = e
                    tree:add(f.map_epc, edt:range(1 + i, 1), e):append_text(
                        " (" .. epc_name(cls, e) .. ")")
                end
            end
        end
    end
    local parts = {}
    for _, e in ipairs(epcs) do parts[#parts + 1] = string.format("%02X", e) end
    return string.format("%d properties [%s]", n, table.concat(parts, " "))
end

local function decode_instlist(tree, edt)
    local n = edt:range(0, 1):uint()
    tree:add(f.inst_count, edt:range(0, 1))
    local parts = {}
    local i = 1
    while i + 2 < edt:len() and #parts < n do
        local r = edt:range(i, 3)
        local v = r:uint()
        tree:add(f.inst_eoj, r):set_text("EOJ: " .. eoj_string(v))
        parts[#parts + 1] = string.format("%06X", v)
        i = i + 3
    end
    return string.format("%d instances [%s]", n, table.concat(parts, " "))
end

local function decode_classlist(tree, edt)
    local n = edt:range(0, 1):uint()
    tree:add(f.cls_count, edt:range(0, 1))
    local parts = {}
    local i = 1
    while i + 1 < edt:len() and #parts < n do
        local r = edt:range(i, 2)
        tree:add(f.cls_code, r)
        parts[#parts + 1] = string.format("%04X", r:uint())
        i = i + 2
    end
    return string.format("%d classes [%s]", n, table.concat(parts, " "))
end

local function hexstr(edt)
    return tostring(edt:bytes())
end

-- Returns a human readable string for the EDT, or nil.
-- May add subtrees for structured values.
local function decode_value(tree, cls, epc, edt, pinfo)
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
        return string.format("%s #%d", LOCATION_NAMES[loc] or "Reserved", bit.band(v, 0x07))
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

-- Dissect `count` properties starting at offset. Returns new offset, list of EPC strings.
local function dissect_props(tvb, pinfo, tree, offset, count, cls, label)
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
        local name = epc_name(cls, epc)
        local pt = tree:add(f.prop, tvb:range(offset, 2 + avail))
        pt:set_text(string.format("%sProperty #%d: EPC 0x%02X (%s), PDC %d",
            label and (label .. " ") or "", i, epc, name, pdc))
        pt:add(f.epc, tvb:range(offset, 1)):append_text(" (" .. name .. ")")
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
                local ok, val = pcall(decode_value, et, cls, epc, edt, pinfo)
                if ok and val then
                    et:add(f.value, edt, val)
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

    local ehd1 = tvb:range(0, 1):uint()
    local ehd2 = tvb:range(1, 1):uint()
    local tid  = tvb:range(2, 2):uint()
    root:add(f.ehd1, tvb:range(0, 1))
    root:add(f.ehd2, tvb:range(1, 1))
    root:add(f.tid,  tvb:range(2, 2))

    if ehd2 == 0x82 then
        if len > 4 then root:add(f.payload, tvb:range(4)) end
        pinfo.cols.info = string.format("Arbitrary message format, TID=%d, %d bytes", tid, len - 4)
        root:append_text(string.format(", Format 2, TID: %d", tid))
        return len
    end

    if len < 12 then
        root:add_proto_expert_info(ef_short, "Frame shorter than the 12-byte minimum")
        pinfo.cols.info = string.format("Truncated ECHONET Lite frame, TID=%d", tid)
        return len
    end

    local edata = root:add(f.edata, tvb:range(4))
    edata:set_text("EDATA")
    local seoj = add_eoj(edata, f.seoj, tvb:range(4, 3), "SEOJ")
    local deoj = add_eoj(edata, f.deoj, tvb:range(7, 3), "DEOJ")
    local esv = tvb:range(10, 1):uint()
    local esv_item = edata:add(f.esv, tvb:range(10, 1))
    if ESV_DESC[esv] then
        esv_item:append_text(" - " .. ESV_DESC[esv])
    else
        esv_item:add_proto_expert_info(ef_unk_esv)
    end
    if esv >= 0x50 and esv <= 0x5F then esv_item:add_proto_expert_info(ef_sna) end

    -- Properties are described in terms of the object that owns them:
    -- requests (0x6x) and INFC_Res (0x7A) refer to DEOJ,
    -- other responses/notifications (0x5x/0x7x) come from SEOJ.
    local owner = ((esv >= 0x60 and esv <= 0x6F) or esv == 0x7A) and deoj or seoj
    local cls = bit.rshift(owner, 8)

    local offset = 11
    local info_props
    if SETGET_ESV[esv] then
        local opcset = tvb:range(offset, 1):uint()
        edata:add(f.opcset, tvb:range(offset, 1))
        local epcs_set, epcs_get
        offset, epcs_set = dissect_props(tvb, pinfo, edata, offset + 1, opcset, cls, "Set")
        if offset < len then
            local opcget = tvb:range(offset, 1):uint()
            edata:add(f.opcget, tvb:range(offset, 1))
            offset, epcs_get = dissect_props(tvb, pinfo, edata, offset + 1, opcget, cls, "Get")
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
        offset, epcs = dissect_props(tvb, pinfo, edata, offset + 1, opc, cls, nil)
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

local udp_table = DissectorTable.get("udp.port")
local current_port = el.prefs.udp_port
udp_table:add(current_port, el)
el:register_heuristic("udp", heuristic)

function el.prefs_changed()
    if current_port ~= el.prefs.udp_port then
        if current_port ~= 0 then udp_table:remove(current_port, el) end
        current_port = el.prefs.udp_port
        if current_port ~= 0 then udp_table:add(current_port, el) end
    end
end
