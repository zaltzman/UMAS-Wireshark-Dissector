--[[
    lua wireshark addon for the UMAS embeded MODBUS protocol 
	Modified by Amir Zaltzman
	Based on the research "From Pass-the-Hash to Code Execution on Schneider Electric M340 PLCs," presented at Black Hat Europe 2024.  
	https://www.blackhat.com/eu-24/briefings/schedule/#from-pass-the-hash-to-code-execution-on-schneider-electric-m340-plcs-42573
    Originally created by biero-el-corridor
--]]

local requests_data = {} -- Table to store requests data

-- functions that made the concordance of the umas_code -> funtions meaning
function get_umas_function_name(code)
    local code_name = "Unknown"
    if 	   code == 0x01 then code_name = "INIT_COMM: Initialize a UMAS communication"
    elseif code == 0x02 then code_name = "READ_ID: Request a PLC ID"
    elseif code == 0x03 then code_name = "READ_PROJECT_INFO: Read Project Information"
    elseif code == 0x04 then code_name = "READ_PLC_INFO: Get internal PLC Info"
	elseif code == 0x05 then code_name = "READ_LOADER_INFO: Get loader Info" -- Added
    elseif code == 0x06 then code_name = "READ_CARD_INFO: Get internal PLC SD-Card Info"
	elseif code == 0x07 then code_name = "READ_BLOCK_INFO: Get block Info" -- Added
    elseif code == 0x0A then code_name = "REPEAT: Sends back data sent to the PLC (used for synchronization)"
    elseif code == 0x10 then code_name = "TAKE_PLC_RESERVATION: Assign an owner to the PLC"
    elseif code == 0x11 then code_name = "RELEASE_PLC_RESERVATION: Release the reservation of a PLC"
    elseif code == 0x12 then code_name = "KEEP_ALIVE: Keep alive message"
    elseif code == 0x20 then code_name = "READ_MEMORY_BLOCK: Read a memory block of the PLC"
	elseif code == 0x21 then code_name = "WRITE_MEMORY_BLOCK: Write a memory block of the PLC" -- Added
    elseif code == 0x22 then code_name = "READ_VARIABLES: Read System bits, System Words and Strategy variables"
    elseif code == 0x23 then code_name = "WRITE_VARIABLES: Write System bits, System Words and Strategy variables"
    elseif code == 0x24 then code_name = "READ_COILS_REGISTERS: Read coils and holding registers from PLC"
    elseif code == 0x25 then code_name = "WRITE_COILS_REGISTERS: Write coils and holding registers into PLC"
	elseif code == 0x26 then code_name = "DATA_DICTIONARY: Data dictionary" -- Added
	elseif code == 0x27 then code_name = "DATA_DICTIONARY_PRELOAD: Data dictionary preload" -- Added
	elseif code == 0x28 then code_name = "READ_PHYSICAL_ADDRESS: Read from a physical address" -- Added
	elseif code == 0x29 then code_name = "WRITE_PHYSICAL_ADDRESS: Write to a physical address" -- Added
	elseif code == 0x2A then code_name = "BROWSE_EVENTS: Browse events" -- Added
    elseif code == 0x30 then code_name = "INITIALIZE_UPLOAD: Initialize Strategy upload (copy from engineering PC to PLC)"
    elseif code == 0x31 then code_name = "UPLOAD_BLOCK: Upload (copy from engineering PC to PLC) a strategy block to the PLC"
    elseif code == 0x32 then code_name = "END_STRATEGY_UPLOAD: Finish strategy Upload (copy from engineering PC to PLC)"
    elseif code == 0x33 then code_name = "INITIALIZE_UPLOAD: Initialize Strategy download (copy from PLC to engineering PC)"
    elseif code == 0x34 then code_name = "DOWNLOAD_BLOCK: Download (copy from PLC to engineering PC) a strategy block"
    elseif code == 0x35 then code_name = "END_STRATEGY_DOWNLOAD: Finish strategy Download (copy from PLC to engineering PC)"
	elseif code == 0x36 then code_name = "UMAS_BACKUP: UMAS backup operations" -- Added
	elseif code == 0x37 then code_name = "PRELOAD_BLOCKS: Preload blocks" -- Added
	elseif code == 0x38 then code_name = "UMAS_RESERVED: Signed reserved message function code"
    elseif code == 0x39 then code_name = "READ_ETH_MASTER_DATA: Read Ethernet Master Data"
    elseif code == 0x40 then code_name = "START_PLC: Starts the PLC"
    elseif code == 0x41 then code_name = "STOP_PLC: Stops the PLC"
	elseif code == 0x42 then code_name = "INIT_PLC: Initiates the PLC" -- Added
	elseif code == 0x43 then code_name = "SWAP: Swap blocks" -- Added
    elseif code == 0x50 then code_name = "MONITOR_PLC: Monitors variables, Systems bits and words"
	elseif code == 0x51 then code_name = "GET_AUTO_MODIF: Get auto modifications" -- Added
	elseif code == 0x52 then code_name = "GET_FORCED_BITS: Get forced bits" -- Added
	elseif code == 0x53 then code_name = "GET_SELECTED_BLOCKS: Get selected blocks" -- Added
    elseif code == 0x58 then code_name = "CHECK_PLC: Check PLC Connection status"
	elseif code == 0x60 then code_name = "BKPT_SET: Set a breakpoint" -- Added
	elseif code == 0x61 then code_name = "BKPT_DEL: Delete or reset a breakpoint" -- Added
	elseif code == 0x62 then code_name = "STEP_OVER: Steps over" -- Added
	elseif code == 0x63 then code_name = "STEP_IN: Steps in" -- Added
	elseif code == 0x64 then code_name = "STEP_OUT: Steps out" -- Added
	elseif code == 0x65 then code_name = "GET_CALL_STACK: Get call stack" -- Added
	elseif code == 0x66 then code_name = "CHECK_DEBUG_ALLOWED: Checks if debug is allowed" -- Added
	elseif code == 0x6C then code_name = "PROCESS_MSG: Special process message mode" -- Added
	elseif code == 0x6D then code_name = "PRIVATE: Private message operations" -- Added
	elseif code == 0x6E then code_name = "RESERVATION_NONCES: Reservation nonces exchange" -- Added
    elseif code == 0x70 then code_name = "READ_IO_OBJECT: Read IO Object"
    elseif code == 0x71 then code_name = "WRITE_IO_OBJECT: WriteIO Object"
	elseif code == 0x72 then code_name = "READ_RACK: Read rack info" -- Added
    elseif code == 0x73 then code_name = "GET_STATUS_MODULE: Get Status Module"
	elseif code == 0x74 then code_name = "READ_DEVICE_DATA: Read device data" -- Added
    elseif code == 0xfe then code_name = "RESPONSE_OK: The PLC response is OK"
    elseif code == 0xfd then code_name = "RESPONSE_ERROR: The PLC response is an error" 
	end
    return code_name
end

modbus1_protocol = Proto("MODBUS1", "MODBUS .")
umas_protocol = Proto("UMAS", "UMAS .")

-- resource that worth your time https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html

----------- MODBUS protocol part ---------------
Transaction_Identifier  = ProtoField.uint16("MODBUS1.Transaction_Identifier"  , "Transaction_Identifier"  , base.DEC)
Protocol_Identifier     = ProtoField.uint16("MODBUS1.Protocol_Identifier"     , "Protocol_Identifier"     , base.DEC)
Length                  = ProtoField.uint16("MODBUS1.Length"                  , "Length"                  , base.DEC)
Unit_Identifier         = ProtoField.int8("MODBUS1.Unit_Identifier"           , "Unit_Identifier"         , base.DEC)
modbus1_protocol.fields = {Transaction_Identifier, Protocol_Identifier, Length, Unit_Identifier}
-------------------------------------------------------

----------- UMAS protocol part -----------------
Function_Code           = ProtoField.uint8("UMAS.Function_Code"         , "Function_Code"         , base.HEX)
Session_Key             = ProtoField.uint8("UMAS.Session_Key"           , "Session_Key"           , base.HEX)
Magic	                = ProtoField.uint8("UMAS.Magic"             	, "Magic"           	  , base.HEX)
Signature               = ProtoField.bytes("UMAS.Signature"             , "Signature")
Request_Function_Code   = ProtoField.uint8("UMAS.Request_Function_Code" , "Request_Function_Code" , base.HEX)
UMAS_Function_Code      = ProtoField.uint8("UMAS.UMAS_Function_Code"    , "UMAS_Function_Code"    , base.HEX)
UMAS_Data               = ProtoField.bytes("UMAS.UMAS_Data"             , "UMAS_Data")
umas_protocol.fields    = {Function_Code, Session_Key, Magic, Signature, Request_Function_Code, UMAS_Function_Code, UMAS_Data}
-------------------------------------------------------

function modbus1_protocol.dissector(buffer,pinfo,tree)
    -- get the size of the packet sections 
    length = buffer:len()

    ------------------------------------------
    -- BEGIN OF THE MODBUS SECTIONS ----------
    ------------------------------------------

    -- if the sections is empty , terminate the process
    if length == 0 then return end
    
    -- apply the name in the column if the protocol is detected
    pinfo.cols.protocol = modbus1_protocol.name
	
    -- add the layer umas in the list of potential layer 
    local subtree       = tree:add(modbus1_protocol, buffer()      , "MODBUS Protocol Data")
    local modbusSubtree = subtree:add(modbus1_protocol, buffer()   , "MODBUS Header")
	
	local tid = buffer(0,2):uint()

    modbusSubtree:add(Transaction_Identifier   ,buffer(0,2))
    modbusSubtree:add(Protocol_Identifier      ,buffer(2,2))
    modbusSubtree:add(Length                   ,buffer(4,2))
    modbusSubtree:add(Unit_Identifier          ,buffer(6,1))
    ------------------------------------------
    -- END OF THE MODBUS SECTIONS ------------
    ------------------------------------------

    ------------------------------------------
    -- BEGIN OF THE UMAS SECTIONS ------------
    ------------------------------------------

    local umas_identifier = buffer(7,1):le_uint()
	local umas_code = buffer(9,1):le_uint()
	local umas_code_name = get_umas_function_name(umas_code)
	
	if umas_identifier == 90
	then
		local umasSubtree = subtree:add(modbus1_protocol ,buffer()   ,"UMAS")
		umasSubtree:add(Function_Code, buffer(7,1))
		umasSubtree:add(Session_Key, buffer(8,1))
		
		if umas_code == 0xfe
		then
			if requests_data[tid]
			then
				if requests_data[tid][2] == 1
				then
					umas_code_name = get_umas_function_name(umas_code)
					umas_code_resp_name = string.format("Response to 0x%02X, Transaction_ID %d, Signed", requests_data[tid][1], tid)
					umasSubtree:add(UMAS_Function_Code,buffer(9,1)):append_text(" (" .. umas_code_name .. ")")
					umasSubtree:add(Request_Function_Code,requests_data[tid][1]):append_text(" (" .. umas_code_resp_name .. ")")
					umasSubtree:add(Magic, buffer(10,1))
					umasSubtree:add(Signature,  buffer(11,32))
					umasSubtree:add(Function_Code, buffer(43,1))
					umasSubtree:add(Session_Key, buffer(44,1))
					umas_code = buffer(45,1):le_uint()
					umas_code_name = get_umas_function_name(umas_code)
					umasSubtree:add(UMAS_Function_Code, buffer(45,1)):append_text(" (" .. umas_code_name .. ")")
					umasSubtree:add(UMAS_Data, buffer(46))
					
					-- requests_data[tid] = nil -- Remove the corresponding request from requests_data
				else
					umas_code_name = get_umas_function_name(umas_code)
					umas_code_resp_name = string.format("Response to 0x%02X, Transaction_ID %d", requests_data[tid][1], tid)
					umasSubtree:add(UMAS_Function_Code,buffer(9,1)):append_text(" (" .. umas_code_name .. ")")
					umasSubtree:add(Request_Function_Code,requests_data[tid][1]):append_text(" (" .. umas_code_resp_name .. ")")
					umasSubtree:add(UMAS_Data, buffer(10))
				end	
			else
				umasSubtree:add(UMAS_Function_Code,buffer(9,1)):append_text(" (" .. umas_code_name .. ")")
				umasSubtree:add(UMAS_Data, buffer(10))
			end
		else
			if umas_code == 0x38
			then
				umasSubtree:add(UMAS_Function_Code, buffer(9,1)):append_text(" (" .. umas_code_name .. ")")
				umasSubtree:add(Magic, buffer(10,1))
				umasSubtree:add(Signature, buffer(11,32))
				umasSubtree:add(Function_Code, buffer(43,1))
				umasSubtree:add(Session_Key, buffer(44,1))
				umas_code = buffer(45,1):le_uint()
				umas_code_name = get_umas_function_name(umas_code)
				umasSubtree:add(UMAS_Function_Code, buffer(45,1)):append_text(" (" .. umas_code_name .. ")")
				umasSubtree:add(UMAS_Data, buffer(46))
				
				requests_data[tid] = {umas_code, 1} -- Append requset to 'requests_data' array with signed flag
			else
				umasSubtree:add(UMAS_Function_Code, buffer(9,1)):append_text(" (" .. umas_code_name .. ")")
				umasSubtree:add(UMAS_Data, buffer(10))
				
				requests_data[tid] = {umas_code, 0} -- Append requset to 'requests_data' array without signed flag
			end
		end
	end
    ------------------------------------------
    -- END OF THE UMAS SECTIONS ------------
    ------------------------------------------ 
end


local modbus = DissectorTable.get("tcp.port")
modbus:add(502, modbus1_protocol)

